using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.IO;

namespace Encrypt
{
    public partial class mainForm : Form
    {
        public mainForm()
        {
            InitializeComponent();
        }

        /**
         * This function will disable the password input box if the user chooses to
         * decrypt a file.
         * If the user chooses to encrypt, it will reset the input boxes to original
         * enabled values.
         */
        private void encryptDecrypt_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (encryptDecrypt.SelectedItem.ToString() == "Decrypt")
            {
                manualKey.Enabled = true;
                passwordInput.Enabled = false;
                manualCheck.Enabled = false;
                manualCheck.Checked = true;

                // Reminds the user to update the input and output files so the user
                // does not accidentally try to decrypt a plaintext file.
                MessageBox.Show("Remember to update the input and output files.");
            }
            else if (encryptDecrypt.SelectedItem.ToString() == "Encrypt")
            {
                manualCheck.Enabled = true;
                passwordInput.Enabled = true;
                manualKey.Enabled = false;
            }
        }

        /**
         * This function will enable or disable input boxes depending on if the
         * checkbox is ticked or not
         */
        private void manualCheck_CheckedChanged(object sender, EventArgs e)
        {
            if (manualCheck.Checked == true)
            {
                manualKey.Enabled = true;
                passwordInput.Enabled = false;
            }
            else if (manualCheck.Checked == false)
            {
                manualKey.Enabled = false;
                passwordInput.Enabled = true;
            }
        }

        /**
         * The main bulk of the program will execute when the user click on the 'Go!'
         * button. Once the user has input the necessary parameters such as the
         * password, input file, output file, and whether to encrypt or decrypt. This
         * function will perform the programs purpose.
         */
        private void runProgram_Click(object sender, EventArgs e)
        {
            // Allows program to continue if password length is correct
            int validPasswordChecker = 0;

            // Only used if the user is using a password
            if (manualCheck.Checked == false)
            {
                // If password conforms to specified guidelines then allows program to
                // continue
                if ((passwordInput.Text.Length >= 10) && (passwordInput.Text.Length <=
                40))
                {
                    validPasswordChecker = 1;
                }
                else
                {
                    MessageBox.Show("Please Enter a Password between 10 and 40
                                     characters.");
                    passwordInput.Focus();
                }
            }

            // If password is not used (greyed out) then allows the program to
            // unconditionally continue.
            else
            {
                validPasswordChecker = 1;
            }

            if (validPasswordChecker == 1)
            {
                string key = string.Empty;

                // If user is using a password then a key will be created from the
                // user supplied password.
                if (manualCheck.Checked == false)
                {
                    string password = string.Empty;
                    int passwordLength;

                    password = passwordInput.Text;
                    passwordLength = password.Length;

                    // This will call the generateKey function to create the key and
                    // return the value into 'key'.
                    key = generateKey(password, passwordLength);
                }

                // If the user specifies a manual key, then 'key' will be what the
                // user specifies in the manual key input box.
                else if (manualCheck.Checked == true)
                {
                    key = manualKey.Text;
                }

                // Reads the source file that the user has specified.
                byte[] inputData = File.ReadAllBytes(openFileDialog1.FileName);

                // This block will only execute if the user chooses to encrypt.
                if (encryptDecrypt.SelectedItem.ToString() == "Encrypt")
                {
                    //Writes key to a file IF key exists.
                    if (key != null)
                    {
                        byte[] keyFile = Encoding.ASCII.GetBytes(key);
                        string keyDirectory = string.Empty;
                        keyDirectory =Path.GetDirectoryName(saveFileDialog1.FileName);
                        File.WriteAllBytes(keyDirectory+@"\key.txt", keyFile);
                    }

                    //Calls the encryptData function to perfom the file encryption.
                    try
                    {
                        // Encrypts the file by calling the encryptFile function.
                        byte[] encryptedData = encryptFile(inputData, key);
                        File.WriteAllBytes(saveFileDialog1.FileName, encryptedData);
                        MessageBox.Show("File successfully encrypted with key: " + key);
                    }
                    catch
                    {
                        MessageBox.Show("Please enter a key!");
                    }
                }

                // This block will only execute if the user chooses to decypt.
                else if (encryptDecrypt.SelectedItem.ToString() == "Decrypt")
                {
                    // For decryption, the user must specify the key manually
                    key = manualKey.Text;

                    try
                    {
                        // Decrypts the encrypted file by calling the decryptFile
                        // function.
                        byte[] decryptedData = decryptFile(inputData, key);
                        File.WriteAllBytes(saveFileDialog1.FileName, decryptedData);
                        MessageBox.Show("File successfully decrypted with key: "+key);
                    }
                    catch (Exception)
                    {
                        MessageBox.Show("Please Enter a key!");
                    }
                }
            }
        }



        /**
         * This funtion is used to generate a key that will used in a poly-alphabetic
         * substitution cipher. The key will be generated by subjecting the user
         * supplied password to a vernam cipher (symmetric stream cipher)
         * and then performing a mono-alphabetic substitution cipher.
         */
        public static string generateKey(string userPassword, int keyLength)
        {
            /**
             * lowerAscii       - Sets lowest ASCII value to a space ' '
             * upperAscii       - Sets highest ASCII value to tilde '~'.
             * rnd              - Used to generate a random number.
             * randomChar       - This will generate a random character within the
             *                    ASCII range specified.
             * charCollection   - This is the collection of each randomly generated
             *                    character.
             * asciiBytesInput  - This will extrapolate the ASCII values of each
             *                    character in the user supplied password.
             * asciiBytesRandom - This will extrapolate the ASCII values of each
             *                    character in the charCollection variable.
             * cKey             - This will hold the value of an individual character
             *                    in the key.
             * sKey             - This will hold the value of the key after a
             *                    symmetric stream cipher has been applied.
             * fKey             - This will hold the value of the final key after sKey
             *                    has undergone a mono-alphabetic substitution cipher.
             */

            int lowerAscii = 32;
            int upperAscii = 126;
            Random rnd = new Random();
            int randomChar;
            string charCollection = string.Empty;
            byte[] asciiBytesInput = Encoding.ASCII.GetBytes(userPassword);

            // This will generate a random character X number of times, where X is the
            // length of characters in the user defined passphrase. It will then add
            // each random character to the charCollection string.
            for (int i = 0; i < keyLength; i++)
            {
                randomChar = Convert.ToInt32((upperAscii - lowerAscii) *
                rnd.NextDouble() + lowerAscii);

                charCollection += (char)randomChar;
            }

            byte[] asciiBytesRandom = Encoding.ASCII.GetBytes(charCollection);

            // This will perform a symmetreic stream cipher on the user supplied
            // password.
            int cKey;
            string sKey = string.Empty;

            // This looping block will take the ASCII value of the user supplied
            // password and XOR it with the ASCII value of the corresponding random
            // character. It will then modulus 95 as this is the amount of legal
            // characters specified in this program.
            for (int i = 0; i < keyLength; i++)
            {
                cKey = ((asciiBytesRandom[i] ^ asciiBytesInput[i]) % 95) + lowerAscii;
                sKey += (char)cKey;
            }

            // This will perform a mono-alphabetic substitution cipher on sKey.
            char[] chars = sKey.ToCharArray();

            // This loop tells the program to shift each character to the right by X
            // places where X is the password length.
            for (int s = 0; s < keyLength; s++)
            {
                chars[s] = (char)(((int)chars[s]) + keyLength);

                //This will make an ASCII character that has reached the end of the
                // ASCII table to loop back to the beginning of the table.
                if (chars[s] >= 127)
                {
                    chars[s] = (char)(((int)chars[s]) - 95);
                }
            }

            string fKey = string.Empty;
            fKey = new string(chars);

            // Returns the final key value to be used for file encryption
            return fKey;
        }


        /**
         * This function will encrypt the file with a poly-alphabetic substitution
         * cipher. The plaintext file will be passed into this function and called
         * 'plainText'. The key will also be passed into this function. The key index
         * is used to allow the program to know which character to encrypt using which
         * key character. The modulus is 127 as this is the earlier defined upper
         * character to use in the ASCII table (~).
         */
        public static Byte[] encryptFile(Byte[] plainText, string key)
        {
            Byte[] encryptedText = new Byte[plainText.Length];
            key = key.Trim();
            int keyIndex = 0;
            int keyLength = key.Length;

            for (int i = 0; i < plainText.Length; i++)
            {
                keyIndex = keyIndex % keyLength;
                int shift = (int)key[keyIndex];
                encryptedText[i] = (byte)(((int)plainText[i] + shift) % 127);
                keyIndex++;

                // This is invoked if the ASCII characters value exceeds 127, in this
                // case the character will be
                // looped back to the start of the ASCII table (e.g 128 (invalid
                // character) will become 33 (!)).
                if (encryptedText[i] >= 127)
                {
                    encryptedText[i] = (byte)(((int)encryptedText[i]) - 95);
                }
            }

            return encryptedText;
        }

        /**
         * This functions the same way as the encryptFile function but is invoked to
         * decrypt a file. The difference here is that the ASCII value is increased by
         * 127 (The upper ascii limit) before being reduced by the shift.
         */
        public static Byte[] decryptFile(Byte[] cipherText, string key)
        {
            Byte[] decryptedText = new Byte[cipherText.Length];
            key = key.Trim();
            int keyIndex = 0;
            int keyLength = key.Length;

            for (int i = 0; i < cipherText.Length; i++)
            {
                keyIndex = keyIndex % keyLength;
                int shift = (int)key[keyIndex];
                decryptedText[i] = (byte)(((int)cipherText[i] + 127 - shift) % 127);
                keyIndex++;

                // This is invoked if the ASCII characters value exceeds 127, in this
                // case the character will be looped back to the start of the ASCII
                // table (e.g 128 (invalid character) will become 33 (!)). This will
                // ensure the character is the same as the original plaintext.
                if (decryptedText[i] >= 127)
                {
                    decryptedText[i] = (byte)(((int)decryptedText[i]) - 95);
                }
            }

            return decryptedText;
        }

        //Needed to allow the user to specify a source file.
        private void fileInput_Click(object sender, EventArgs e)
        {
            if (openFileDialog1.ShowDialog() == DialogResult.OK)
            {

            }
        }

        //Needed to allow the user to specify an output file.
        private void fileOutput_Click(object sender, EventArgs e)
        {
            if (saveFileDialog1.ShowDialog() == DialogResult.OK)
            {

            }
        }
    }
}
