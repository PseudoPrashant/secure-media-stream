import os

BASE = "secure-media-stream"


folders = [
    f"{BASE}/sender",
    f"{BASE}/receiver",
    f"{BASE}/shared",
    f"{BASE}/logs",
]


files = {
    f"{BASE}/sender/sender.py": "# sender.py - Main sender logic\n",
    f"{BASE}/sender/frame_generator.py": "# frame_generator.py - Simulates video frames\n",
    f"{BASE}/receiver/receiver.py": "# receiver.py - Main receiver logic\n",
    f"{BASE}/receiver/validator.py": "# validator.py - Packet validation & integrity checks\n",
    f"{BASE}/shared/packet.py": "# packet.py - Custom packet structure (build & parse)\n",
    f"{BASE}/shared/encryption.py": "# encryption.py - AES-256 GCM encrypt/decrypt\n",
    f"{BASE}/shared/config.py": "# config.py - Shared settings (port, host, keys)\n",
    f"{BASE}/logs/.gitkeep": "",  
    f"{BASE}/requirements.txt": "cryptography\nnumpy\n",
    f"{BASE}/README.md": "# secure-media-stream\n\nA prototype system for secure media frame transmission over a network.\n",
}

def setup():
    print("Setting up secure-media-stream project...\n")


    for folder in folders:
        os.makedirs(folder, exist_ok=True)
        print(f"  Created folder:  {folder}/")

    print()


    for filepath, content in files.items():
        with open(filepath, "w") as f:
            f.write(content)
        print(f"  Created file:    {filepath}")

    print("\nAll done! Your project structure is ready.")
    print("Next step: cd into secure-media-stream and start coding!")

if __name__ == "__main__":
    setup()