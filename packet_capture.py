from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw


def analyze(packet):

    if IP in packet:

        print("\n================")

        print(
            "Source IP:",
            packet[IP].src
        )

        print(
            "Destination IP:",
            packet[IP].dst
        )

        if TCP in packet:

            print(
                "Protocol: TCP"
            )

        elif UDP in packet:

            print(
                "Protocol: UDP"
            )

        else:

            print(
                "Protocol: Other"
            )

        if Raw in packet:

            try:

                payload = (
                    packet[Raw]
                    .load[:80]
                    .decode(
                        errors="ignore"
                    )
                )

                if payload.strip():

                    print(
                        "Payload:"
                    )

                    print(
                        payload
                    )

                else:

                    print(
                        "Payload: No readable payload"
                    )

            except:

                print(
                    "Payload: Encrypted/Binary Data"
                )

        else:

            print(
                "Payload: Not Available"
            )


print(
    "Capturing packets..."
)

sniff(
    iface="Wi-Fi",
    timeout=20,
    store=False,
    prn=analyze
)

print(
    "Finished"
) 