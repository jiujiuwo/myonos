COMPILE_DEPS = CORE_DEPS + KRYO + CLI + [
    "//core/store/serializers:onos-core-serializers",
    "//core/store/primitives:onos-core-primitives",
]

osgi_jar_with_tests(
    karaf_command_packages = ["org.onosproject.install"],
    suppress_checkstyle = True,
    deps = COMPILE_DEPS,
)

onos_app(
    category = "Traffic Engineering",
    description = "FlowRule Install",
    title = "FlowRule Install",
    url = "http://onosproject.org",
)
