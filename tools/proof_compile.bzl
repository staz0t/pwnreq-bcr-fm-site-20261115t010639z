"""Action matching production _compile_stardoc_for_module_version."""

def _published_docs_compile_impl(ctx):
    output = ctx.actions.declare_file(ctx.label.name + ".documentationinfo.pb.gz")
    args = ctx.actions.args()
    args.add("--output_file")
    args.add(output)
    args.add_all(ctx.files.srcs)
    ctx.actions.run(
        executable = ctx.file.compiler,
        arguments = [args],
        inputs = ctx.files.srcs,
        outputs = [output],
        mnemonic = "CompileProductionPublishedDocs",
        progress_message = "Compiling production-fetched published documentation %{label}",
    )
    return [DefaultInfo(files = depset([output]))]

published_docs_compile = rule(
    implementation = _published_docs_compile_impl,
    attrs = {
        "compiler": attr.label(allow_single_file = True, mandatory = True),
        "srcs": attr.label_list(allow_files = True, mandatory = True),
    },
)
