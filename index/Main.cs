/* Copyright (c) 2018 Red-EyeX32
*
* This software is provided 'as-is', without any express or implied
* warranty. In no event will the authors be held liable for any damages arising from the use of this software.
*
* Permission is granted to anyone to use this software for any purpose,
* including commercial applications*, and to alter it and redistribute it
* freely, subject to the following restrictions:
*
* 1. The origin of this software must not be misrepresented; you must not
*    claim that you wrote the original software. If you use this software
*    in a product, an acknowledge in the product documentation is required.
*
* 2. Altered source versions must be plainly marked as such, and must not
*    be misrepresented as being the original software.
*
* 3. This notice may not be removed or altered from any source distribution.
*
* *Contact must be made to discuss permission and terms.
*/

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace index
{
    public partial class Main : Form
    {
        // index.dat is found in: /system/priv/etc/index.dat

        private byte[] index_erk = new byte[32] {
            0xEE, 0xD5, 0xA4, 0xFF, 0xE8, 0xA3, 0xC9, 0x10, 0xDC, 0x1B, 0xFD, 0x6A, 0xAF, 0x13, 0x82, 0x25,
            0x0B, 0x38, 0x0D, 0xBA, 0xE5, 0x04, 0x5D, 0x23, 0x05, 0x69, 0x47, 0x3F, 0x46, 0xB0, 0x7B, 0x1F
        };

        private byte[] index_riv = new byte[16] {
            0x3A, 0xCB, 0x38, 0xC1, 0xEC, 0x12, 0x11, 0x9D,
            0x56, 0x92, 0x9F, 0x49, 0xF7, 0x04, 0x15, 0xFF
        };

        public Main()
        {
            InitializeComponent();
        }

        private static byte[] aes_encrypt_cbc(byte[] key, byte[] iv, byte[] input)
        {
            AesManaged aes = new AesManaged();
            aes.Key = key;
            aes.IV = iv;
            aes.KeySize = 256;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.Zeros;

            if (iv.Length != 16)
                Array.Resize(ref iv, 16);

            return aes.CreateEncryptor(key, iv).TransformFinalBlock(input, 0, input.Length);
        }

        private static byte[] aes_decrypt_cbc(byte[] key, byte[] iv, byte[] input)
        {
            AesManaged aes = new AesManaged();
            aes.Key = key;
            aes.IV = iv;
            aes.KeySize = 256;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.Zeros;

            if (iv.Length != 16)
                Array.Resize(ref iv, 16);

            return aes.CreateDecryptor(key, iv).TransformFinalBlock(input, 0, input.Length);
        }

        private static byte[] Sha256(byte[] buffer, int offset, int length)
        {
            var sha = new SHA256Managed();
            sha.TransformFinalBlock(buffer, offset, length);
            return sha.Hash;
        }

        private static bool ArrayEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;

            for (int i = 0; i < a.Length; i++) {
                if (a[i] != b[i])
                    return false;
            }

            return true;
        }

        private void btnDecrypt_Click(object sender, EventArgs e)
        {
            var ofd = new OpenFileDialog();
            ofd.Filter = "DAT file (*.dat)|*.dat";

            if (ofd.ShowDialog() == DialogResult.OK) {
                byte[] data = File.ReadAllBytes(ofd.FileName);
                data = aes_decrypt_cbc(index_erk, index_riv, data);
                
                byte[] stored_hash = new byte[32], computed_hash = new byte[32];
                
                Array.Copy(data, 0, stored_hash, 0, 32);
                computed_hash = Sha256(data, 32, (data.Length - 32));

                if (!ArrayEquals(computed_hash, stored_hash))
                    throw new Exception("warning: invalid hash.");

                File.WriteAllBytes(ofd.FileName, data);
                MessageBox.Show("The file has been successfully decrypted!", "Decrypted", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
            }
        }

        private void btnEncrypt_Click(object sender, EventArgs e)
        {
            var ofd = new OpenFileDialog();
            ofd.Filter = "DAT file (*.dat)|*.dat";

            if (ofd.ShowDialog() == DialogResult.OK) {
                byte[] data = File.ReadAllBytes(ofd.FileName);

                byte[] computed_hash = Sha256(data, 32, (data.Length - 32));
                Array.Copy(computed_hash, 0, data, 0, 32);

                data = aes_encrypt_cbc(index_erk, index_riv, data);

                File.WriteAllBytes(ofd.FileName, data);
                MessageBox.Show("The file has been successfully encrypted!", "Encrypted", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
            }
        }
    }
}