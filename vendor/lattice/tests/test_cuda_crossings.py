from lattice.cuda import cuda_crossings


def test_cuda_crossings_reports_memcpy_and_launch_args(tmp_path):
    """The GPU boundary: what data crosses host<->device. cudaMemcpy directions and the
    arguments handed to a kernel launch are the GPU analogue of library exposure."""
    (tmp_path / "k.cu").write_text(
        "__global__ void add(float* y, int n) {}\n"
        "void run(float* h, int n) {\n"
        "  float* d;\n"
        "  cudaMemcpy(d, h, n * 4, cudaMemcpyHostToDevice);\n"
        "  add<<<1, 256>>>(d, n);\n"
        "  cudaMemcpy(h, d, n * 4, cudaMemcpyDeviceToHost);\n"
        "}\n")
    cr = cuda_crossings(str(tmp_path))
    dirs = {c.direction for c in cr}
    assert "host_to_device" in dirs and "device_to_host" in dirs, cr
    launch = [c for c in cr if c.kind == "kernel_launch"]
    assert launch and launch[0].kernel == "add" and "d" in launch[0].crosses, launch
