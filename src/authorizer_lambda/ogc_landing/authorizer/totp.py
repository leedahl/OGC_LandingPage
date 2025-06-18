# MIT License
#
# Copyright (c) 2023
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import base64
import hmac
import hashlib
import secrets
import struct
import time
from typing import Optional


class TimeBasedOneTimePassword:
    """
    Implementation of Time-Based One-Time Password (TOTP) according to RFC 6238.
    
    This class provides methods to generate and validate TOTP codes, which are
    commonly used for two-factor authentication (2FA).
    """
    
    def __init__(self, shared_secret: Optional[str] = None):
        """
        Initialize the TOTP generator with an optional shared secret.
        
        Args:
            shared_secret: Base32 encoded shared secret. If not provided, a new one will be generated.
        """
        if shared_secret:
            self.shared_secret = shared_secret
        else:
            self.shared_secret = self.generate_shared_secret()
    
    @staticmethod
    def generate_shared_secret(length: int = 20) -> str:
        """
        Generate a new random shared secret.
        
        Args:
            length: Length of the secret in bytes before encoding (default: 20)
            
        Returns:
            Base32 encoded shared secret
        """
        # Generate random bytes
        random_bytes = secrets.token_bytes(length)
        
        # Encode as base32 and remove padding
        base32_secret = base64.b32encode(random_bytes).decode('utf-8').rstrip('=')
        
        return base32_secret
    
    def retrieve_code(self, 
                      timestamp: Optional[int] = None, 
                      digits: int = 6, 
                      time_step: int = 30, 
                      hash_algorithm: str = 'sha256') -> str:
        """
        Generate a TOTP code based on the current time and shared secret.
        
        Args:
            timestamp: Unix timestamp (in seconds) to use for code generation.
                      If None, the current time is used.
            digits: Number of digits in the generated code (default: 6)
            time_step: Time step in seconds (default: 30)
            hash_algorithm: Hash algorithm to use (default: 'sha1')
                           Supported values: 'sha256', 'sha512'
                           
        Returns:
            TOTP code as a string
        """
        if timestamp is None:
            timestamp = int(time.time())
        
        # Calculate the time counter (T)
        time_counter = timestamp // time_step
        
        # Convert time counter to bytes (8 bytes, big-endian)
        time_bytes = struct.pack('>Q', time_counter)
        
        # Decode the base32 shared secret
        # Add padding if necessary
        padded_secret = self.shared_secret
        if len(padded_secret) % 8 != 0:
            padded_secret += '=' * (8 - (len(padded_secret) % 8))
        
        key = base64.b32decode(padded_secret)
        
        # Select the hash algorithm
        if hash_algorithm == 'sha256':
            hash_func = hashlib.sha256

        elif hash_algorithm == 'sha512':
            hash_func = hashlib.sha512
            
        else:
            raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")
        
        # Calculate HMAC-SHA hash
        h = hmac.new(key, time_bytes, hash_func).digest()
        
        # Dynamic truncation
        offset = h[-1] & 0x0F
        binary = ((h[offset] & 0x7F) << 24 |
                  (h[offset + 1] & 0xFF) << 16 |
                  (h[offset + 2] & 0xFF) << 8 |
                  (h[offset + 3] & 0xFF))
        
        # Generate code with specified number of digits
        code = binary % (10 ** digits)
        
        # Format code with leading zeros if necessary
        return str(code).zfill(digits)