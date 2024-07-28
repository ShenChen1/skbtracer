#include <string>
#include <vector>
#include <spdlog/spdlog.h>

extern "C" {
#include <gelf.h>
#include <libelf.h>
#include <sys/mman.h>
}

#include "pcap2bpf.h"

namespace cbpf {
extern "C" {
#include <linux/filter.h>
#include <pcap/pcap.h>
}
} /* namespace cbpf */

extern "C" {
int bpf_convert_filter(cbpf::sock_filter *prog, int len,
                       libbpf::bpf_insn *new_prog, int *new_len);
}

static std::pair<int, cbpf::sock_fprog> compile_cbpf_filter(const std::string &filter_str, bool l3)
{
    constexpr int MAXIMUM_SNAPLEN = 262144;
    int err = 0;
    cbpf::sock_fprog sf = { 0, NULL };
    cbpf::bpf_program bf = { 0, NULL };
    cbpf::pcap_t *pcap;
    int linktype = l3 ? DLT_RAW : DLT_EN10MB;

    pcap = cbpf::pcap_open_dead(linktype, MAXIMUM_SNAPLEN);
    if (!pcap) {
        spdlog::error("can not open pcap");
        return { -EFAULT, sf };
    }

    if (cbpf::pcap_compile(pcap, &bf, filter_str.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
        spdlog::error("pcap filter string not valid (%s)", cbpf::pcap_geterr(pcap));
        err = -EINVAL;
        goto end;
    }

    sf.len = bf.bf_len;
    sf.filter = new cbpf::sock_filter[sf.len];
    if (!sf.filter) {
        spdlog::error("failed to allocate memory for sock_filter");
        err = -ENOMEM;
        goto end;
    }
    for (size_t i = 0; i < sf.len; i++) {
        sf.filter[i].code = bf.bf_insns[i].code;
        sf.filter[i].jt = bf.bf_insns[i].jt;
        sf.filter[i].jf = bf.bf_insns[i].jf;
        sf.filter[i].k = bf.bf_insns[i].k;
    }

end:
    cbpf::pcap_freecode(&bf);
    cbpf::pcap_close(pcap);
    return { err, sf };
}

std::tuple<int, libbpf::bpf_insn *, size_t> pcap2bpf::compile_ebpf_filter(const std::string &filter_str, bool l3)
{
    int err = 0;
    libbpf::bpf_insn *ebpf = NULL;
    int ebpf_len = 0;

    auto [ret, cbpf] = compile_cbpf_filter(filter_str, l3);
    if (ret) {
        err = ret;
        goto end;
    }

    /* 1st pass: calculate the eBPF program length */
    err = bpf_convert_filter(cbpf.filter, cbpf.len, NULL, &ebpf_len);
    if (err) {
        spdlog::error("cannot get eBPF length");
        goto end;
    }

    spdlog::info("prog len cBPF={} -> eBPF={}", cbpf.len, ebpf_len);
    ebpf = new libbpf::bpf_insn[ebpf_len];
    if (!ebpf) {
        spdlog::error("failed to allocate memory for eBPF instructions");
        err = -ENOMEM;
        goto end;
    }

    /* 2nd pass: remap cBPF to eBPF instructions */
    err = bpf_convert_filter(cbpf.filter, cbpf.len, ebpf, &ebpf_len);
    if (err) {
        spdlog::error("cannot convert cBPF to eBPF");
        goto end;
    }

end:
    delete[] cbpf.filter;
    return { err, ebpf, ebpf_len };
}

int pcap2bpf::inject_ebpf_filter(const std::string &obj_path, const std::string &function, const libbpf::bpf_insn *prog_data, size_t prog_len)
{
    int err;

    if (elf_version(EV_CURRENT) == EV_NONE) {
        spdlog::error("Failed to initialize libelf");
        return -EINVAL;
    }

    int fd = open(obj_path.c_str(), O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        err = -errno;
        spdlog::error("Failed to create fd");
        return err;
    }

    Elf *elf = elf_begin(fd, ELF_C_RDWR, NULL);
    if (elf == NULL) {
        err = -errno;
        spdlog::error("Failed to open ELF file");
        return err;
    }

    size_t shstrs_sec_idx;
    if (elf_getshdrstrndx(elf, &shstrs_sec_idx)) {
        err = -errno;
        spdlog::warn("failed to get SHSTRTAB section index");
        return err;
    }

    GElf_Shdr shdr;
    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (!gelf_getshdr(scn, &shdr)) {
            continue;
        }

        if (shdr.sh_type == SHT_SYMTAB) {
            break;
        }
    }
    if (!scn) {
        spdlog::error("Failed to find symbol table");
        return -1;
    }

    Elf_Data *sym_data = elf_getdata(scn, 0);
    if (!sym_data) {
        err = -errno;
        spdlog::warn("failed to get SHT_SYMTAB section data");
        return err;
    }

    GElf_Sym sym;
    int idx, nr_syms = sym_data->d_size / shdr.sh_entsize;
    for (idx = 0; idx < nr_syms; ++idx) {
        gelf_getsym(sym_data, idx, &sym);
        const char *func_name = elf_strptr(elf, shdr.sh_link, sym.st_name);
        if (!func_name) {
            continue;
        }

        if (function == func_name) {
            break;
        }
    }
    if (idx == nr_syms) {
        err = -ENOENT;
        spdlog::warn("failed to find function {}", function);
        return err;
    }

    Elf_Scn *target_scn = elf_getscn(elf, sym.st_shndx);
    if (!target_scn) {
        err = -errno;
        spdlog::warn("failed to get section");
        return err;
    }

    GElf_Shdr target_shdr;
    gelf_getshdr(target_scn, &target_shdr);

    GElf_Sym target_sym;
    gelf_getsym(sym_data, idx, &target_sym);

    Elf_Data *target_data = elf_getdata(target_scn, 0);
    if (!target_data) {
        err = -errno;
        spdlog::warn("failed to get section data");
        return err;
    }

    size_t new_size = prog_len * sizeof(libbpf::bpf_insn);
    target_data->d_buf = realloc(target_data->d_buf, target_data->d_size + new_size);
    std::memcpy(reinterpret_cast<char*>(target_data->d_buf) + sym.st_value + new_size, reinterpret_cast<char*>(target_data->d_buf) + sym.st_value, target_data->d_size - sym.st_value);
    std::memcpy(reinterpret_cast<char*>(target_data->d_buf) + sym.st_value, prog_data, new_size);
    target_data->d_size += new_size;

    for (int i = 0; i < nr_syms; ++i) {
        gelf_getsym(sym_data, i, &sym);
        if (sym.st_shndx != target_sym.st_shndx) {
            continue;
        }

        if (target_sym.st_value == sym.st_value) {
            sym.st_size += new_size;
        } else if (target_sym.st_value < sym.st_value) {
            sym.st_value += new_size;
        } else {
            continue;
        }
        gelf_update_sym(sym_data, i, &sym);
    }

    elf_update(elf, ELF_C_WRITE);
    elf_end(elf);
    return 0;
}