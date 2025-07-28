import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk
import os
import sqlite3
import datetime
import hashlib 
import base64  
from cryptography.fernet import Fernet, InvalidToken 

# for encryption and decryption
class SymmetricCipher:

    def _derive_key(self, passphrase: str):
        if not passphrase:
            raise ValueError("Passphrase cannot be empty. Please provide a key.")
        key_hash = hashlib.sha256(passphrase.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(key_hash)

    def encrypt(self, plaintext: str, passphrase: str):
        key = self._derive_key(passphrase)
        f = Fernet(key)
        encrypted_data = f.encrypt(plaintext.encode('utf-8'))
        return encrypted_data

    def decrypt(self, ciphertext: bytes, passphrase: str):
        key = self._derive_key(passphrase)
        f = Fernet(key)
        decrypted_data = f.decrypt(ciphertext)
        return decrypted_data.decode('utf-8')

# Image manipulation
class ImageProcessor:
    TEXT_DELIMITER = b"###END###" 

    def _bytes_to_bits(self, byte_data: bytes):
        bits = []
        for byte in byte_data:
            for i in range(7, -1, -1):  
                bits.append((byte >> i) & 1)
        return bits

    def _bits_to_bytes(self, bit_data: list):
        byte_data = bytearray()
        for i in range(0, len(bit_data), 8):
            byte = 0
            for j in range(8):
                if i + j < len(bit_data):
                    byte = (byte << 1) | bit_data[i + j]
                else:
                    byte = (byte << 1) | 0 
            byte_data.append(byte)
        return bytes(byte_data)

    def hide_data_in_image(self, cover_image_path: str, data_to_hide_bytes: bytes, output_path: str):
        try:
            cover_img = Image.open(cover_image_path).convert("RGB") 

            if cover_img.mode != "RGB":
                raise ValueError("Cover image must be in RGB mode for LSB steganography.")

            data_bits_stream = self._bytes_to_bits(data_to_hide_bytes + self.TEXT_DELIMITER)

            # Calculate the maximum number of bits 
            max_hidden_bits_capacity = cover_img.width * cover_img.height * 3

            if len(data_bits_stream) > max_hidden_bits_capacity:
                raise ValueError(
                    f"Data to hide is too large. It needs {len(data_bits_stream)} bits, "
                    f"but the cover image can only hide {max_hidden_bits_capacity} bits (1 LSB per RGB channel)."
                )

            # pixel access 
            cover_pixels = cover_img.load()
            data_bit_index = 0

            for y in range(cover_img.height):
                for x in range(cover_img.width):
                    r, g, b = cover_pixels[x, y] 

                    new_channels = []
                    for channel_val in [r, g, b]:
                        if data_bit_index < len(data_bits_stream):
                            hidden_bit = data_bits_stream[data_bit_index]
                            new_channel_val = (channel_val & 0xFE) | hidden_bit
                            data_bit_index += 1
                        else:
                            new_channel_val = channel_val & 0xFE 
                        new_channels.append(new_channel_val)
                    
                    cover_pixels[x, y] = tuple(new_channels) 
            
            cover_img.save(output_path, format="PNG")
            return cover_img 

        except FileNotFoundError:
            raise ValueError(f"Cover image file not found at: {cover_image_path}")
        except Exception as e:
            raise ValueError(f"An error occurred during data hiding: {e}")

    def reveal_data_from_image(self, stego_image_path: str):
        try:
            stego_img = Image.open(stego_image_path).convert("RGB") 
            stego_pixels = stego_img.load()

            extracted_bits_stream = []
            for y in range(stego_img.height):
                for x in range(stego_img.width):
                    r, g, b = stego_pixels[x, y]
                    extracted_bits_stream.append(r & 1)
                    extracted_bits_stream.append(g & 1)
                    extracted_bits_stream.append(b & 1)

            extracted_bytes = self._bits_to_bytes(extracted_bits_stream)
            
            try:
                delimiter_index = extracted_bytes.index(self.TEXT_DELIMITER)
                revealed_data_bytes = extracted_bytes[:delimiter_index] 
                return revealed_data_bytes
            except ValueError:
                raise ValueError("No delimiter found in the stego image. Hidden data might be corrupted or not present.")
        except FileNotFoundError:
            raise ValueError(f"Stego image file not found at: {stego_image_path}")
        except Exception as e:
            raise ValueError(f"An error occurred during data revealing: {e}")

# Database 
class DatabaseManager:
    def __init__(self, db_name="steganography_history.db"):
        self.db_name = db_name
        self._create_table() 

    def _create_table(self):
        conn = None
        try:
            conn = sqlite3.connect(self.db_name) 
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS steganography_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    operation_type TEXT NOT NULL,         
                    cover_image_path TEXT,                
                    stego_image_path TEXT,                
                    hidden_text TEXT,                     
                    revealed_text TEXT,                   
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP 
                )
            """)
            conn.commit() 
        except sqlite3.Error as e:
            print(f"Database error during table creation: {e}")
        finally:
            if conn:
                conn.close() 

    def log_operation(self, operation_type: str, cover_path: str = None, 
                      stego_path: str = None, hidden_text: str = None, revealed_text: str = None):
        conn = None
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO steganography_logs (operation_type, cover_image_path, 
                                                stego_image_path, hidden_text, revealed_text)
                VALUES (?, ?, ?, ?, ?)
            """, (operation_type, cover_path, stego_path, hidden_text, revealed_text))
            conn.commit()
            return True 
        except sqlite3.Error as e:
            print(f"Database error logging operation: {e}")
            return False
        finally:
            if conn:
                conn.close()

    def get_all_operations(self):
        conn = None
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM steganography_logs ORDER BY timestamp DESC")
            rows = cursor.fetchall()
            return rows
        except sqlite3.Error as e:
            print(f"Database error fetching operations: {e}")
            return []
        finally:
            if conn:
                conn.close()

# Tkinter GUI
class SteganographyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.withdraw() #show splash screen first
        self.title("Welcome to the Stegano-Cipher Tool")
        self.geometry("1000x800") 
        self.resizable(False, False) 
        #instances of the classes
        self.image_processor = ImageProcessor()
        self.db_manager = DatabaseManager()
        self.cipher = SymmetricCipher() 

        self.cover_image_path = tk.StringVar()     
        self.stego_input_image_path = tk.StringVar()
        self.encryption_key = tk.StringVar()       

        # images in gui
        self.cover_photo = None         
        self.stego_output_photo = None  
        self.stego_input_photo = None

        # widgets
        self._create_widgets()
        self.update_status("Initializing...") 
        self._show_splash_screen() # starts splash screen

    def _show_splash_screen(self):
        splash_screen = tk.Toplevel(self) 
        splash_screen.title("Welcome to the hackers world")
        splash_screen.geometry("700x300")
        splash_screen.overrideredirect(True) 
        splash_screen.config(bg="#000000") 

        # Center splash screen on the monitor
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width / 2) - (700 / 2)
        y = (screen_height / 2) - (300 / 2)
        splash_screen.geometry(f'+{int(x)}+{int(y)}')


        tk.Label(splash_screen, 
                 text="< PROTOCOL INTEGRITY VERIFIED >\n\n"
                      "This cutting-edge tool was developed by Jawad and Taimoor.\n"
                      "Crafted by top-class hackers.",
                 font=("Consolas", 14, "bold"), 
                 fg="#00FF00", 
                 bg="#000000",
                 wraplength=550,
                 justify=tk.CENTER).pack(expand=True, padx=20, pady=20)
        
        def _transition_from_splash():
            splash_screen.destroy() 
            self.deiconify() 
            self._show_start_screen() 

        # transition after 4 seconds
        splash_screen.after(4000, _transition_from_splash)

    def _create_widgets(self):
        self.bg_color = "#1a1a1a" 
        self.fg_color = "#00FF00" 
        self.button_bg = "#006600" 
        self.button_fg = "#00FF00" 
        self.active_button_bg = "#009900" 
        self.frame_bg = "#2a2a2a" 
        self.border_color = "#00FFFF" 
        self.error_fg_color = "red" 
        self.font_large = ("Consolas", 24, "bold")
        self.font_medium = ("Consolas", 16)
        self.font_button = ("Consolas", 12, "bold")
        self.font_small = ("Consolas", 10)
        #image preview
        self.image_preview_width = 200
        self.image_preview_height = 150
        self.config(bg=self.bg_color) #main window bg color

        # Main Frame 
        self.main_container_frame = tk.Frame(self, padx=10, pady=10, bg=self.bg_color)
        self.main_container_frame.pack(expand=True, fill="both")

        # Start Screen 
        self.start_frame = tk.Frame(self.main_container_frame, bg=self.bg_color)
        tk.Label(self.start_frame, text="< Stegano-Cipher >", font=("Consolas", 28, "bold"), fg=self.fg_color, bg=self.bg_color).pack(pady=30)
        tk.Label(self.start_frame, text="Choose Operational Protocol:", font=self.font_medium, fg=self.fg_color, bg=self.bg_color).pack(pady=20)

        button_frame = tk.Frame(self.start_frame, bg=self.bg_color)
        button_frame.pack(pady=20)
        
        # Encode Text to Image Button 
        tk.Button(button_frame, text="ENCODE TEXT TO IMAGE", command=lambda: self._show_encode_screen("text_to_image"),
                  font=self.font_button, bg=self.button_bg, fg=self.button_fg, 
                  padx=20, pady=10, relief=tk.RAISED, bd=3, activebackground=self.active_button_bg,
                  highlightbackground=self.border_color, highlightthickness=1).pack(side=tk.LEFT, padx=20)
        
        # Decode Text from Image Button 
        tk.Button(button_frame, text="DECODE TEXT FROM IMAGE", command=lambda: self._show_decode_screen("text_from_image"),
                  font=self.font_button, bg=self.button_bg, fg=self.button_fg, 
                  padx=20, pady=10, relief=tk.RAISED, bd=3, activebackground=self.active_button_bg,
                  highlightbackground=self.border_color, highlightthickness=1).pack(side=tk.RIGHT, padx=20)


        # Encode (Text to Image) Section 
        self.encode_text_frame = tk.LabelFrame(self.main_container_frame, text="ENCODE: TEXT TO IMAGE WITH ENCRYPTION", 
                                               padx=10, pady=10, relief=tk.GROOVE, bd=2, fg=self.fg_color, bg=self.frame_bg,
                                               highlightbackground=self.border_color, highlightcolor=self.border_color, font=self.font_medium)
        self.encode_text_frame.grid_columnconfigure(0, weight=1)
        self.encode_text_frame.grid_columnconfigure(1, weight=1)

        # Cover Image selection widgets
        tk.Label(self.encode_text_frame, text="Stganographic Medium:", font=self.font_small, fg=self.fg_color, bg=self.frame_bg).grid(row=0, column=0, pady=5, sticky="w")
        tk.Entry(self.encode_text_frame, textvariable=self.cover_image_path, width=40, state='readonly', bg="#3a3a3a", fg=self.fg_color, insertbackground=self.fg_color, font=self.font_small, relief=tk.FLAT).grid(row=0, column=1, padx=5, pady=2, sticky="ew")
        tk.Button(self.encode_text_frame, text="Select Image", command=self._select_cover_image,
                  font=self.font_small, bg=self.button_bg, fg=self.button_fg, activebackground=self.active_button_bg).grid(row=0, column=2, padx=5, pady=5)
        # Label to display the cover image preview
        self.cover_image_label_text_mode = tk.Label(self.encode_text_frame, text="NO MEDIUM SELECTED", width=self.image_preview_width, height=self.image_preview_height, relief="solid", bd=2, bg="#000000", fg="#00FF00", font=("Consolas", 10))
        self.cover_image_label_text_mode.grid(row=1, column=0, columnspan=3, pady=5, sticky="nsew")

        # Text to Encrypt input area
        tk.Label(self.encode_text_frame, text="Source Message:", font=self.font_small, fg=self.fg_color, bg=self.frame_bg).grid(row=2, column=0, pady=5, sticky="w")
        self.text_input_area = scrolledtext.ScrolledText(self.encode_text_frame, wrap=tk.WORD, width=50, height=6, font=self.font_small, bg="#3a3a3a", fg=self.fg_color, insertbackground=self.fg_color, relief=tk.FLAT, bd=2, highlightbackground=self.border_color, highlightthickness=1)
        self.text_input_area.grid(row=2, column=1, columnspan=2, padx=5, pady=2, sticky="ew")

        # Encryption Key input
        tk.Label(self.encode_text_frame, text="Encryption Key (Passphrase):", font=self.font_small, fg=self.fg_color, bg=self.frame_bg).grid(row=3, column=0, pady=5, sticky="w")
        tk.Entry(self.encode_text_frame, textvariable=self.encryption_key, width=40, show="*", bg="#3a3a3a", fg=self.fg_color, insertbackground=self.fg_color, font=self.font_small, relief=tk.FLAT).grid(row=3, column=1, columnspan=2, padx=5, pady=2, sticky="ew")

        # Initiate Encoding Button
        tk.Button(self.encode_text_frame, text="ACTIVATE CRYPTO-EMBED PROTOCOL", command=self._hide_text_action, 
                  bg="#009900", fg="#FFFFFF", font=self.font_button, padx=10, pady=5, relief=tk.RAISED, bd=3, activebackground="#00CC00",
                  highlightbackground=self.border_color, highlightthickness=1).grid(row=4, column=0, columnspan=3, pady=10, sticky="ew")
        
        # Stego Output Image preview label
        tk.Label(self.encode_text_frame, text="Encapsulated Data Image:", font=self.font_small, fg=self.fg_color, bg=self.frame_bg).grid(row=5, column=0, pady=5, sticky="w")
        self.stego_output_label_text_mode = tk.Label(self.encode_text_frame, text="RENDER: INJECTED HOST IMAGE", width=self.image_preview_width, height=self.image_preview_height, relief="solid", bd=2, bg="#000000", fg="#00FF00", font=("Consolas", 10))
        self.stego_output_label_text_mode.grid(row=6, column=0, columnspan=3, pady=5, sticky="nsew")
        # Download button for the stego image
        self.stego_download_button_text_mode = tk.Button(self.encode_text_frame, text="DOWNLOAD STEGO-TARGET", command=self._download_stego_image_text_mode, state=tk.DISABLED, 
                                                bg="#444444", fg="#FFFFFF", font=self.font_small, activebackground="#666666",
                                                highlightbackground=self.border_color, highlightthickness=1)
        self.stego_download_button_text_mode.grid(row=7, column=0, columnspan=3, pady=5, sticky="ew")

        # Back button to return to the main operation selection
        tk.Button(self.encode_text_frame, text="< REVERT TO COMMAND CONSOLE >", command=self._show_start_screen,
                  font=self.font_small, bg="#666666", fg="#FFFFFF", relief=tk.FLAT, bd=0, activebackground="#888888").grid(row=8, column=0, columnspan=3, pady=10, sticky="ew")


        # --- Decode (Text from Image) Section Frame ---
        # This frame contains all widgets for revealing and decrypting text from an image.
        self.decode_text_frame = tk.LabelFrame(self.main_container_frame, text="DECODE: TEXT FROM IMAGE WITH DECRYPTION", 
                                               padx=10, pady=10, relief=tk.GROOVE, bd=2, fg=self.fg_color, bg=self.frame_bg,
                                               highlightbackground=self.border_color, highlightcolor=self.border_color, font=self.font_medium)
        self.decode_text_frame.grid_columnconfigure(0, weight=1)
        self.decode_text_frame.grid_columnconfigure(1, weight=1)

        # Stego Image selection widgets
        tk.Label(self.decode_text_frame, text="Steged Image (Input):", font=self.font_small, fg=self.fg_color, bg=self.frame_bg).grid(row=0, column=0, pady=5, sticky="w")
        tk.Entry(self.decode_text_frame, textvariable=self.stego_input_image_path, width=40, state='readonly', bg="#3a3a3a", fg=self.fg_color, insertbackground=self.fg_color, font=self.font_small, relief=tk.FLAT).grid(row=0, column=1, padx=5, pady=2, sticky="ew")
        tk.Button(self.decode_text_frame, text="Select Steged Image", command=self._select_stego_input_image_for_text,
                  font=self.font_small, bg=self.button_bg, fg=self.button_fg, activebackground=self.active_button_bg).grid(row=0, column=2, padx=5, pady=5)
        # Label to display the stego image preview
        self.stego_input_label_text_mode = tk.Label(self.decode_text_frame, text="NO IMAGE SELECTED", width=self.image_preview_width, height=self.image_preview_height, relief="solid", bd=2, bg="#000000", fg="#00FF00", font=("Consolas", 10))
        self.stego_input_label_text_mode.grid(row=1, column=0, columnspan=3, pady=5, sticky="nsew")

        # Decryption Key input
        tk.Label(self.decode_text_frame, text="Decryption Key (Passphrase):", font=self.font_small, fg=self.fg_color, bg=self.frame_bg).grid(row=2, column=0, pady=5, sticky="w")
        tk.Entry(self.decode_text_frame, textvariable=self.encryption_key, width=40, show="*", bg="#3a3a3a", fg=self.fg_color, insertbackground=self.fg_color, font=self.font_small, relief=tk.FLAT).grid(row=2, column=1, columnspan=2, padx=5, pady=2, sticky="ew")

        # Initiate Decoding Button
        tk.Button(self.decode_text_frame, text="ACTIVATE DECRYPTO-REVEAL PROTOCOL", command=self._reveal_text_action, 
                  bg="#009900", fg="#FFFFFF", font=self.font_button, padx=10, pady=5, relief=tk.RAISED, bd=3, activebackground="#00CC00",
                  highlightbackground=self.border_color, highlightthickness=1).grid(row=3, column=0, columnspan=3, pady=10, sticky="ew")
        
        # Revealed Text Output area
        tk.Label(self.decode_text_frame, text="Revealed Text Output:", font=self.font_small, fg=self.fg_color, bg=self.frame_bg).grid(row=4, column=0, pady=5, sticky="w")
        self.revealed_text_area = scrolledtext.ScrolledText(self.decode_text_frame, wrap=tk.WORD, width=50, height=8, font=self.font_small, state='disabled', bg="#3a3a3a", fg=self.fg_color, insertbackground=self.fg_color, relief=tk.FLAT, bd=2, highlightbackground=self.border_color, highlightthickness=1)
        self.revealed_text_area.grid(row=5, column=0, columnspan=3, padx=5, pady=2, sticky="ew")

        # Back button to return to the main operation selection
        tk.Button(self.decode_text_frame, text="< REVERT TO COMMAND CONSOLE >", command=self._show_start_screen,
                  font=self.font_small, bg="#666666", fg="#FFFFFF", relief=tk.FLAT, bd=0, activebackground="#888888").grid(row=6, column=0, columnspan=3, pady=10, sticky="ew")


        # Displays real-time messages to the user about the application's state.
        self.status_bar = tk.Label(self, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W, bg="#000000", fg="#00FF00", font=("Consolas", 10))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def _show_all_frames_forget(self):
        self.start_frame.pack_forget()
        self.encode_text_frame.pack_forget()
        self.decode_text_frame.pack_forget()

    def _show_start_screen(self):
        self._show_all_frames_forget() # Hide all other screens
        self.start_frame.pack(expand=True, fill="both") # Show the start screen
        self.update_status("Welcome! Choose to Encode or Decode Text.")
        self.title("Stegano-Cipher: Encrypted Text")

        # --- Clear all input fields and reset previews ---
        self.cover_image_path.set("")
        self.stego_input_image_path.set("")
        self.text_input_area.delete("1.0", tk.END) # Clear ScrolledText widget
        self.encryption_key.set("") # Clear passphrase field
        self.revealed_text_area.config(state='normal') # Enable to clear
        self.revealed_text_area.delete("1.0", tk.END) # Clear ScrolledText output
        self.revealed_text_area.config(state='disabled') # Disable again

        # Reset image preview labels by passing None as img_path
        self._display_image_on_label(None, self.cover_image_label_text_mode)
        self._display_image_on_label(None, self.stego_output_label_text_mode)
        self._display_image_on_label(None, self.stego_input_label_text_mode)
        self.stego_download_button_text_mode.config(state=tk.DISABLED) # Disable download button

    def _show_encode_screen(self, mode: str):
        self._show_all_frames_forget() # Hide all other screens
        
        self.cover_image_path.set("")
        self.text_input_area.delete("1.0", tk.END)
        self.encryption_key.set("") 
        self._display_image_on_label(None, self.cover_image_label_text_mode)
        self._display_image_on_label(None, self.stego_output_label_text_mode)
        self.stego_download_button_text_mode.config(state=tk.DISABLED)

        self.encode_text_frame.pack(expand=True, fill="both") 
        self.update_status("ENCODE PROTOCOL: Ready to hide encrypted text in image.")
        self.title("Stegano-Cipher: Encrypt & Encode Text")

    def _show_decode_screen(self, mode: str):
        
        self._show_all_frames_forget() 
    
        self.stego_input_image_path.set("")
        self.encryption_key.set("") 
        self._display_image_on_label(None, self.stego_input_label_text_mode) 
        self.revealed_text_area.config(state='normal') 
        self.revealed_text_area.delete("1.0", tk.END) 
        self.revealed_text_area.config(state='disabled') 

        self.decode_text_frame.pack(expand=True, fill="both") 
        self.update_status("DECODE PROTOCOL: Ready to reveal and decrypt text from image.")
        self.title("Stegano-Cipher: Decode & Decrypt Text")

    def update_status(self, message: str):
        self.status_bar.config(text=message)
        self.update_idletasks() 

    def _resize_image_for_display(self, img: Image.Image, max_width: int, max_height: int) -> Image.Image:
        if img.width > max_width or img.height > max_height:
            ratio = min(max_width / img.width, max_height / img.height)
            new_width = int(img.width * ratio)
            new_height = int(img.height * ratio)
            img = img.resize((new_width, new_height), Image.Resampling.LANCZOS) 
        return img

    def _display_image_on_label(self, img_path: str, label_widget: tk.Label):
        default_text_map = {
            self.cover_image_label_text_mode: "NO IMAGE SELECTED",
            self.stego_output_label_text_mode: "OUTPUT: STEGO IMAGE (TEXT)",
            self.stego_input_label_text_mode: "NO IMAGE SELECTED"
        }
        original_text = default_text_map.get(label_widget, "") 
        if not img_path or not os.path.exists(img_path):
            
            label_widget.config(image="", text=original_text, fg=self.fg_color) 
            label_widget.image = None # 
            return None

        try:
            pil_image = Image.open(img_path)
            display_width = self.image_preview_width
            display_height = self.image_preview_height

            resized_image = self._resize_image_for_display(pil_image, display_width, display_height)

            
            photo_image = ImageTk.PhotoImage(resized_image)
            label_widget.config(image=photo_image, text="", fg=self.fg_color) 
            label_widget.image = photo_image 
            return photo_image 
        except Exception as e:
            label_widget.config(image="", text=f"ERROR: {e}", fg=self.error_fg_color)
            label_widget.image = None
            return None

    # File Selection 
    def _select_cover_image(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.bmp"), ("All files", "*.*")])
        if file_path:
            self.cover_image_path.set(file_path) 
            
            self.cover_photo = self._display_image_on_label(file_path, self.cover_image_label_text_mode)
            self.update_status(f"STATUS: COVER IMAGE '{os.path.basename(file_path)}' LOADED.")
            
            self._display_image_on_label(None, self.stego_output_label_text_mode)
            self.stego_download_button_text_mode.config(state=tk.DISABLED)


    def _select_stego_input_image_for_text(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.bmp"), ("All files", "*.*")])
        if file_path:
            self.stego_input_image_path.set(file_path) 
            self.stego_input_photo = self._display_image_on_label(file_path, self.stego_input_label_text_mode)
            self.update_status(f"STATUS: STEGO IMAGE (TEXT MODE) '{os.path.basename(file_path)}' LOADED.")
            
            self.revealed_text_area.config(state='normal') 
            self.revealed_text_area.delete("1.0", tk.END) 
            self.revealed_text_area.config(state='disabled') 


    # Hide/Reveal Text with Encryption
    def _hide_text_action(self):
        cover_path = self.cover_image_path.get()
        plaintext_to_hide = self.text_input_area.get("1.0", tk.END).strip() 
        encryption_passphrase = self.encryption_key.get()

        if not cover_path:
            messagebox.showerror("INPUT ERROR", "Please select a cover image.")
            return
        if not plaintext_to_hide:
            messagebox.showerror("INPUT ERROR", "Please enter text to hide.")
            return
        if not encryption_passphrase:
            messagebox.showerror("INPUT ERROR", "Please enter an encryption key (passphrase).")
            return

        output_stego_path = filedialog.asksaveasfilename(
            defaultextension=".png", 
            filetypes=[("PNG files", "*.png")], 
            initialfile="stego_encrypted_text.png" 
        )
        if not output_stego_path:
            self.update_status("OPERATION CANCELLED: Save dialog closed.")
            return 

        self.update_status("ENCODING IN PROGRESS: Encrypting and hiding text... <INITIATING>\n" + "-"*50)
        try:
            encrypted_data_bytes = self.cipher.encrypt(plaintext_to_hide, encryption_passphrase)
            
            stego_pil_image = self.image_processor.hide_data_in_image(cover_path, encrypted_data_bytes, output_stego_path)

            # generated stego image preview
            self.stego_output_photo = self._display_image_on_label(output_stego_path, self.stego_output_label_text_mode)
            self.stego_download_button_text_mode.config(state=tk.NORMAL) 
            
            # Log the operation to the database
            self.db_manager.log_operation("encode_text_to_image_encrypted", 
                                          cover_path=cover_path, 
                                          stego_path=output_stego_path, 
                                          hidden_text=plaintext_to_hide) 
            self.update_status(f"ENCODING COMPLETE: Encrypted text hidden successfully! Output to: {os.path.basename(output_stego_path)}")
            messagebox.showinfo("OPERATION SUCCESSFUL", "Encrypted text hidden successfully!")

        except ValueError as e:
            messagebox.showerror("ENCODING FAILED", str(e))
            self.update_status(f"ENCODING ABORTED: {e}")
        except Exception as e:
            messagebox.showerror("SYSTEM ERROR", f"An unexpected error occurred during encoding: {e}")
            self.update_status(f"SYSTEM ERROR: Encoding failed unexpectedly: {e}")

    def _reveal_text_action(self):
        stego_path = self.stego_input_image_path.get()
        decryption_passphrase = self.encryption_key.get() 

        if not stego_path:
            messagebox.showerror("INPUT ERROR", "Please select a steged image to reveal text from.")
            return
        if not decryption_passphrase:
            messagebox.showerror("INPUT ERROR", "Please enter the decryption key (passphrase).")
            return

        self.update_status("DECODING IN PROGRESS: Revealing and decrypting text... <INITIATING>\n" + "-"*50)
        try:
            encrypted_data_bytes = self.image_processor.reveal_data_from_image(stego_path)
            revealed_plaintext_content = self.cipher.decrypt(encrypted_data_bytes, decryption_passphrase)

            # revealed plaintext
            self.revealed_text_area.config(state='normal') 
            self.revealed_text_area.delete("1.0", tk.END) 
            self.revealed_text_area.insert(tk.END, revealed_plaintext_content) 
            self.revealed_text_area.config(state='disabled') 

            self.db_manager.log_operation("decode_text_from_image_encrypted", 
                                          stego_path=stego_path, 
                                          revealed_text=revealed_plaintext_content) 
            self.update_status(f"DECODING COMPLETE: Text revealed and decrypted successfully! Check output area.")
            messagebox.showinfo("OPERATION SUCCESSFUL", "Text revealed and decrypted successfully!")

        except InvalidToken:
            messagebox.showerror("DECRYPTION FAILED", "Incorrect decryption key or corrupted data. Please ensure the key is correct.")
            self.update_status("DECRYPTION FAILED: Invalid key or corrupted data.")

            self.revealed_text_area.config(state='normal')
            self.revealed_text_area.delete("1.0", tk.END)
            self.revealed_text_area.insert(tk.END, "<ERROR: DECRYPTION FAILED - INVALID KEY OR CORRUPTED DATA>")
            self.revealed_text_area.config(state='disabled')
        except ValueError as e:
            messagebox.showerror("DECODING FAILED", str(e))
            self.update_status(f"DECODING ABORTED: {e}")
        except Exception as e:
            messagebox.showerror("SYSTEM ERROR", f"An unexpected error occurred during decoding: {e}")
            self.update_status(f"SYSTEM ERROR: Decoding failed unexpectedly: {e}")


    def _download_stego_image_text_mode(self):
        messagebox.showinfo("DOWNLOAD INFO", "The Stego Image has been saved to the location you chose during the hiding process.")

# start
if __name__ == "__main__":
    app = SteganographyApp() 
    app.mainloop() 
