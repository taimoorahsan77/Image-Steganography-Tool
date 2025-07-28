# Image-Steganography-Tool

# Stegano-Cipher Tool

# Overview

The Stegano-Cipher Tool is a robust and user-friendly desktop application built with Python, designed for secure data concealment and retrieval. It leverages image steganography (Least Significant Bit - LSB method) to hide encrypted textual messages within image files, making the presence of the secret message virtually undetectable to the casual observer. For enhanced security, all hidden messages are first encrypted using symmetric encryption (Fernet), ensuring confidentiality even if the stego-image is intercepted. The application also maintains a log of all steganography operations in an SQLite database.

This tool provides a graphical user interface (GUI) built with Tkinter, offering an intuitive experience for both encoding (hiding and encrypting) and decoding (revealing and decrypting) messages.

## Features
The Stegano-Cipher Tool comes equipped with a comprehensive set of features to handle secure data embedding and extraction:

## Image Steganography (LSB Method):
Hide Text in Image: Embeds any textual message into a .png or .bmp cover image by manipulating the least significant bits of the image's pixel data.
Reveal Text from Image: Extracts hidden textual messages from a stego-image, reversing the LSB process.
Capacity Check: Automatically verifies if the chosen cover image has sufficient capacity to hide the entire message, preventing data loss.

## Symmetric Encryption & Decryption:
Secure Data Hiding: Before embedding, the plaintext message is encrypted using the Fernet symmetric encryption scheme, which is based on AES in CBC mode.
Passphrase-Derived Key: The encryption/decryption key is securely derived from a user-provided passphrase using SHA-256 hashing, eliminating the need to store or transmit the actual key.
Robust Decryption: Ensures that only users with the correct passphrase can decrypt and reveal the hidden message.

## Intuitive Graphical User Interface (GUI):
Tkinter Framework: Built using Python's standard Tkinter library for a cross-platform desktop application.
Operation Selection: A clear start screen allows users to choose between "Encode Text to Image" and "Decode Text from Image" protocols.
File Dialogs: Utilizes standard file dialogs for easy selection of cover and stego images.
Real-time Image Previews: Displays both the original cover image and the generated stego-image (or the input stego-image) within the application for visual confirmation.
Status Bar: Provides real-time feedback and messages to the user about the application's current state and operation progress.
Custom Splash Screen: Features a themed splash screen upon startup, enhancing the user experience.

## Operation Logging (SQLite Database):
History Tracking: All encoding and decoding operations are automatically logged into a local SQLite database (steganography_history.db).
Detailed Records: Each log entry includes the operation type, paths to cover/stego images, the hidden/revealed text (for reference), and a timestamp.
Persistent Storage: The database ensures that a history of operations is maintained across application sessions.

## Robust Error Handling:
User Feedback: Provides clear and informative error messages (via messagebox) for common issues like missing files, insufficient image capacity, empty inputs, or incorrect decryption keys.
Input Validation: Basic validation for user inputs (e.g., ensuring passphrases are not empty).

## Technologies Used
Python 3.x: The core programming language for the application logic.
Tkinter: Python's standard GUI toolkit, used for building the graphical user interface.
Pillow (PIL Fork): A powerful image processing library used for opening, manipulating (pixel access), and saving image files.
cryptography library: Specifically, the Fernet module for symmetric encryption and hashlib for SHA-256 hashing to derive encryption keys.
sqlite3: Python's built-in library for interacting with SQLite databases, used for logging operations.
os module: For interacting with the operating system, such as checking file existence and managing file paths.

## Requirements / Prerequisites
To run this application, you need:
Python 3.x: Download and install from python.org.
Required Python Libraries: You can install these using pip:
pip install Pillow cryptography

(Tkinter and sqlite3 are usually included with standard Python installations.)

## How to Run the Application
Clone the Repository:
First, clone this GitHub repository to your local machine using Git:
git clone https://github.com/taimoorahsan77/Image-Steganography-Tool.git
cd Image-Steganography Tool


## Install Dependencies:
Navigate into the cloned directory and install the necessary Python libraries:
pip install Pillow cryptography


## Run the Application:
Execute the main Python script:
python final_version_of_Steganocipher.py

The application's GUI window will appear after a brief splash screen.

# How It Works (Technical Explanation)

## Steganography (LSB Method)
The core steganography mechanism relies on the Least Significant Bit (LSB) technique. Digital images are composed of pixels, and each pixel is made up of color channels (e.g., Red, Green, Blue for RGB images). Each color channel is represented by a set of bits (typically 8 bits, from 0 to 255). The LSB method works by altering the very last bit (the least significant bit) of each color channel. Changing this bit has a negligible effect on the overall color of the pixel, making the alteration visually imperceptible.
Hiding: The binary representation of the secret message (after encryption) is embedded bit by bit into the LSB of consecutive pixel color channels. A special delimiter (###END###) is added to the end of the message to mark its conclusion.
Revealing: The process is reversed. The LSB of each color channel in the stego-image is read sequentially until the delimiter is encountered, reconstructing the hidden binary data.

## Encryption
For robust security, the textual message is encrypted before being hidden.
Fernet Symmetric Encryption: The cryptography.fernet module is used, which implements symmetric authenticated encryption. This means the same key is used for both encryption and decryption, and it also ensures that the data has not been tampered with.
Key Derivation: Instead of directly using the user's passphrase as the encryption key, the passphrase is first hashed using SHA-256. This hash is then base64 URL-safe encoded to generate the actual Fernet key. This protects the original passphrase and ensures the key is in the correct format for Fernet.

## Database Logging
All operations (encoding and decoding) are logged into an SQLite database (steganography_history.db). This database stores:
operation_type: "encode_text_to_image_encrypted" or "decode_text_from_image_encrypted"
cover_image_path: Path to the original image (for encoding).
stego_image_path: Path to the image with hidden data.
hidden_text: The original plaintext hidden (for encoding logs).
revealed_text: The decrypted plaintext revealed (for decoding logs).
timestamp: When the operation occurred.
This provides an audit trail of all steganography activities performed using the tool.

## Screenshots
Splash Screen
The initial welcoming screen that appears upon launching the application.
Encode Text to Image
The main interface for hiding encrypted text within a selected image.
Decode Text from Image
The interface for revealing and decrypting hidden text from a stego-image.

## Future Enhancements
Support for More File Types: Extend steganography capabilities to other file formats (e.g., audio, video).
Advanced Steganography Techniques: Implement more sophisticated steganography methods beyond LSB.
Performance Optimization: For very large images or data, optimize the hiding/revealing algorithms.
GUI Enhancements: Further refine the user interface for a more polished look and feel, potentially adding progress bars for long operations.
Key Management: Implement more advanced key management features, such as key generation or secure key storage options.
Database Viewer: Add a GUI component to view the steganography_history.db logs directly within the application.

## License
This project is open-source and available under the MIT License.

