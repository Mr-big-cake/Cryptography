using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace Bob
{
    /// <summary>
    /// Логика взаимодействия для MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private string _InputFile;
        private string _OutputFile;
        public MainWindow()
        {
            InitializeComponent();

            Encryptor.ProgressChanged += (progress) =>
            {
                App.Current.Dispatcher.Invoke(() =>
                {

                });
            };

            //System.Diagnostics.Process.Start("_Alice.exe");
            try
            {
                IPEndPoint ipPoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 8005);

                Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                // подключаемся к удаленному хосту
                socket.Connect(ipPoint);


                // получаем ответ
                var data = new byte[256]; // буфер для ответа
                StringBuilder builder = new StringBuilder();
                int bytes = 0; // количество полученных байт

                do
                {
                    bytes = socket.Receive(data, data.Length, 0);
                    builder.Append(Encoding.Unicode.GetString(data, 0, bytes));
                }
                while (socket.Available > 0);

                InfoTextBox.Text = "Open key  = " + builder.ToString();

                string[] splitsWords = builder.ToString().Split(' ');

                LUC.PublicKey = BigInteger.Parse( splitsWords[0]);
                LUC.N = BigInteger.Parse( splitsWords[1]);

                data = new byte[16];
                bytes = 0;
                do
                {
                    bytes = socket.Receive(data);
                } while (socket.Available > 0);
                Encryptor.IV = data;
                InfoTextBox.Text += "\nIV = " + new BigInteger(Encryptor.IV);

                BigInteger keyToBigInt = new BigInteger(LUC.Encrypt (FROG.Key));
                

                socket.Send(Encoding.Unicode.GetBytes(keyToBigInt.ToString()));
                InfoTextBox.Text += "\nSession key = " + new BigInteger(FROG.Key);
                //InfoTextBox.Text += "\n chiper session key = " + keyToBigInt.ToString(); 
                //// закрываем сокет
                socket.Shutdown(SocketShutdown.Both);
                socket.Close();
            }
            catch (Exception ex)
            {
                InfoTextBox.Text += "\n--->" + DateTime.Now + ": " + ex.Message;
            }
        }

        private void RadioButtonChangeEncryptMode(object sender, RoutedEventArgs e)
        {
            if (ECB.IsChecked == true) Encryptor.encryptionMode = Encryptor.EncryptionMode.ECB;
            else if (CBC.IsChecked == true) Encryptor.encryptionMode = Encryptor.EncryptionMode.CBC;
            else if (CFB.IsChecked == true) Encryptor.encryptionMode = Encryptor.EncryptionMode.CFB;
            else if (OFB.IsChecked == true) Encryptor.encryptionMode = Encryptor.EncryptionMode.OFB;
        }


        private void EncryptClick(object sender, RoutedEventArgs e)
        {
            try
            {
                Encryptor.EncryptFile(_InputFile, _OutputFile, progressBar);
                InfoTextBox.Text += "\n--->Encryption file = " + _InputFile + "->" + Encryptor.encryptionMode;
            }
            catch
            {
                InfoTextBox.Text += "\n--->" + DateTime.Now + ": " + "Ошибка в открытии входного файла";
            }

        }

        private void DecryptClick(object sender, RoutedEventArgs e)
        {
            try
            {

                Encryptor.DecryptFile(_InputFile, _OutputFile, progressBar);
                InfoTextBox.Text += "\nDecryption file = " + _InputFile + "->" + Encryptor.encryptionMode;
            }
            catch
            {
                InfoTextBox.Text += "\n" + DateTime.Now + ": " + "Ошибка в открытии выходного файла";
            }
        }

        private void InputButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dialog = new OpenFileDialog();
            if (dialog.ShowDialog() == true)
            {
                _InputFile = dialog.FileName;
            }

            TextBlockNameInput.Text = _InputFile;
        }

        private void OutputButton_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog dialog = new SaveFileDialog();
            if (dialog.ShowDialog() == true)
            {
                _OutputFile = dialog.FileName;
            }

            TextBlockNameOutput.Text = _OutputFile;
        }
    }
}
