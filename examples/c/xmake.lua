add_rules("mode.release", "mode.debug")
add_rules("platform.linux.bpf")
set_license("GPL-2.0")

option("system-libbpf",      {showmenu = true, default = false, description = "Use system-installed libbpf"})
option("require-bpftool",    {showmenu = true, default = false, description = "Require bpftool package"})

add_requires("libelf", "zlib")
if is_plat("android") then
    add_requires("ndk >=22.x", "argp-standalone")
    set_toolchains("@ndk", {sdkver = "23"})
else
    add_requires("llvm >=10.x")
    set_toolchains("@llvm")
    add_requires("linux-headers")
end

add_includedirs("../../vmlinux")

-- we can run `xmake f --require-bpftool=y` to pull bpftool from xmake-repo repository
if has_config("require-bpftool") then
    add_requires("linux-tools", {configs = {bpftool = true}})
    add_packages("linux-tools")
else
    before_build(function (target)
        os.addenv("PATH", path.join(os.scriptdir(), "..", "..", "tools"))
    end)
end

-- we use the vendored libbpf sources for libbpf-bootstrap.
-- for some projects you may want to use the system-installed libbpf, so you can run `xmake f --system-libbpf=y`
if has_config("system-libbpf") then
    add_requires("libbpf", {system = true})
else
    target("libbpf")
        set_kind("static")
        set_basename("bpf")
        add_files("../../libbpf/src/*.c")
        add_includedirs("../../libbpf/include")
        add_includedirs("../../libbpf/include/uapi", {public = true})
        add_includedirs("$(buildir)", {interface = true})
        add_configfiles("../../libbpf/src/(*.h)", {prefixdir = "bpf"})
        add_packages("libelf", "zlib")
        if is_plat("android") then
            add_defines("__user=", "__force=", "__poll_t=uint32_t")
        end
end

target("pinned")
    set_kind("binary")
    add_files("pinned*.c")
    add_packages("linux-headers")
    if not has_config("system-libbpf") then
        add_deps("libbpf")
    end
