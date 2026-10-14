from capture.managed_capture import parse_tshark_interfaces


def test_parse_linux_tshark_interfaces() -> None:
    output = "1. eth0\n2. any\n3. lo (Loopback)\n"
    assert parse_tshark_interfaces(output) == [
        ("eth0", "eth0"),
        ("any", "any"),
        ("lo", "Loopback"),
    ]


def test_parse_windows_tshark_interfaces() -> None:
    output = (
        "1. \\Device\\NPF_{A1B2} (Ethernet)\n"
        "2. \\Device\\NPF_Loopback (Adapter for loopback traffic capture)\n"
    )
    assert parse_tshark_interfaces(output) == [
        ("\\Device\\NPF_{A1B2}", "Ethernet"),
        ("\\Device\\NPF_Loopback", "Adapter for loopback traffic capture"),
    ]
