import shutil
import pytest

clang_ok = True
try:
    import clang.cindex  # noqa
    clang.cindex.Index.create()
except Exception:
    clang_ok = False
pytestmark = pytest.mark.skipif(not clang_ok, reason="libclang not available")


def test_cpp_ingest_functions_classes_inheritance_and_calls(tmp_path):
    from lattice.ingest.cpp import cpp_ingest
    (tmp_path / "a.cpp").write_text(
        "int helper() { return 2; }\n"
        "struct Base { virtual int tag() { return 1; } };\n"
        "struct Derived : Base {\n"
        "    int tag() override { return helper(); }\n"
        "};\n")
    raw = cpp_ingest(tmp_path)
    names = {s.name for s in raw.symbols}
    assert {"Base", "Derived", "tag", "helper"} <= names, names
    d = next(s for s in raw.symbols if s.name == "Derived")
    assert "Base" in d.extends                              # C++ inheritance
    assert any(r.kind == "references" for r in raw.references)


def test_cpp_ingest_plain_h_headers(tmp_path):
    from lattice.ingest.cpp import cpp_ingest
    (tmp_path / "plain.h").write_text(
        "struct HeaderThing { int value() const { return 7; } };\n"
        "inline int header_helper() { return HeaderThing{}.value(); }\n")
    raw = cpp_ingest(tmp_path)
    names = {s.name for s in raw.symbols}
    assert {"HeaderThing", "value", "header_helper"} <= names, names


def test_cuda_kernel_is_ingested_as_a_function(tmp_path):
    """A .cu file parses (CUDA keywords macro'd out) and its __global__ kernel becomes a
    function vertex — the GPU code the tool must be able to see."""
    from lattice.ingest.cpp import cpp_ingest
    (tmp_path / "k.cu").write_text(
        "__global__ void addKernel(const float* x, float* y, int n) {\n"
        "    int i = blockIdx.x * blockDim.x + threadIdx.x;\n"
        "    if (i < n) y[i] = x[i] + 1.0f;\n"
        "}\n")
    raw = cpp_ingest(tmp_path)
    assert "addKernel" in {s.name for s in raw.symbols}


def test_cuda_kernel_launch_wires_host_to_kernel(tmp_path):
    """A kernel launch `addKernel<<<g,b>>>(...)` must create a host->kernel edge so
    reachability/impact/taint follow from host code INTO the GPU kernel — the host/device
    boundary. The `<<<>>>` doesn't parse as C++, so it's recovered by a source scan."""
    from lattice.ingest.cpp import cpp_ingest
    from lattice.graph.builder import build
    from lattice.graph.query import GraphView
    (tmp_path / "k.cu").write_text(
        "__global__ void addKernel(float* y, int n) {\n"
        "    int i = threadIdx.x; if (i < n) y[i] += 1.0f;\n"
        "}\n"
        "void run(float* y, int n) {\n"
        "    addKernel<<<1, 256>>>(y, n);\n"
        "}\n")
    raw = cpp_ingest(tmp_path)
    assert any((r.to_file or "").endswith("k.cu") for r in raw.references), \
        [r.__dict__ for r in raw.references]
    net = build(raw)
    run = next(v for v in net.vertices if v.name == "run")
    reach = GraphView(net).reachable_from(run.id)
    assert any("addKernel" in r for r in reach), f"host launch not wired to kernel: {reach}"
