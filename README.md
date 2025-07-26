# PYdroid--Hack--project

## Hackathon: PYDroid by Android Club

---

## Problem Statement

Develop a comprehensive steganographic system that encrypts secret messages and embeds them within digital media files, then provides secure extraction and decryption capabilities to recover the original hidden information.

---

## Overview

This project demonstrates an advanced steganographic platform designed for secure information hiding within digital media (images, audio, and video). The system combines robust encryption (AES-256 GCM) with Least Significant Bit (LSB) steganography, enabling covert communication and digital watermarking for defense, privacy, and intellectual property protection.

---

## Key Features

- **AES-256 GCM Encryption:** Ensures confidentiality and integrity of hidden messages.
- **RSA Key Exchange (Conceptual):** Demonstrates secure symmetric key sharing using public-key cryptography.
- **LSB Steganography for Images:** Embeds encrypted data in the least significant bits of image pixels.
- **Modular Design:** Easily extendable to audio and video steganography.
- **Key Management:** Secure generation, storage, and loading of cryptographic keys.
- **Error Handling:** Robust checks for file existence, capacity, and decryption integrity.
- **Visualization:** Side-by-side comparison of original and stego images for demonstration.
- **User Interaction:** Interactive scenario selection for testing image and audio steganography.

---

## How It Works

1. **Encryption:** Secret messages are encrypted using AES-256 GCM.
2. **Embedding:** Encrypted data is converted to a bitstream and embedded into the LSBs of a cover image (or audio file).
3. **Extraction:** The system retrieves the embedded bitstream from the stego media.
4. **Decryption:** The extracted data is decrypted to recover the original message.

---

## Usage

1. **Setup:**  
   - Place your cover images in the `Sample images (.png)` folder.
   - Place your audio files in the `Sample audio files (.mp3)` folder (for future extension).
   - Run the main notebook or script.

2. **Interactive Scenarios:**  
   - Choose between image or audio steganography.
   - Enter your secret message and password.
   - The system will encrypt, embed, and visualize the results.
   - Extract and decrypt the hidden message using the correct password.

---

## Advanced Considerations

- **Steganalysis Resistance:** Future work includes adaptive LSB, DCT domain embedding for JPEGs, and error correction codes.
- **Media Format Support:** Planned extensions for audio (WAV/MP3) and video (MP4/AVI) steganography.
- **Key Management:** Secure storage and out-of-band key exchange for real-world deployment.
- **Performance:** Benchmarking for speed and capacity across media types.

---

## Team

- Project by: The Encryptors
- Hackathon: PYDroid by Android Club
- Date: July 2025

---

## Disclaimer

This project is for educational and research purposes only. Responsible and ethical use is paramount.

---
