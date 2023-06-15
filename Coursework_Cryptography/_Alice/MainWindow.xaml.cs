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
namespace _Alice
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
            //создаем сокет
            IPEndPoint ipPoint = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 8005);
            Socket listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                // связываем сокет с локальной точкой, по которой будем принимать данные
                listenSocket.Bind(ipPoint); //связывает объект Socket с локальной конечной точкой

                // начинаем прослушивание входящих запросов
                listenSocket.Listen(10); //В качестве параметра он принимает 
                //количество входящих подключений, которые могут быть поставлены в очередь сокета.



                Socket handler = listenSocket.Accept(); //если подключения приходят на сокет,
                                                        //то их можно получить с помощью метода Accept - 
                                                        // Accept извлекает из очереди ожидающих запрос первый запрос
                                                        //и создает для его обработки объект Socket. Если очередь запросов пуста, то метод Accept блокирует вызывающий поток до появления нового подключения.

                // отправляем открытые ключи
                
                string message = LUC.PublicKey + " " + LUC.N;
                var data = Encoding.Unicode.GetBytes(message);
                InfoTextBox.Text += "Open key: " + message;
                handler.Send(data);

                InfoTextBox.Text += "\nIV = " + new BigInteger( Encryptor.IV);
                handler.Send(Encryptor.IV);
                

                // получаем зашифрованый сеансовый ключ
                StringBuilder builder = new StringBuilder();
                int bytes = 0; // количество полученных байтов
                data = new byte[256]; // буфер для получаемых данных
                do
                {
                    bytes = handler.Receive(data); // Метод Receive в качестве параметра принимает массив байтов, в который считываются полученные данные, и возвращает количество полученных байтов.
                    builder.Append(Encoding.Unicode.GetString(data, 0, bytes));
                }
                while (handler.Available > 0);

                //InfoTextBox.Text += "\nChiper session key = " + builder.ToString();
                
                var result = LUC.Decrypt (BigInteger.Parse(builder.ToString()).ToByteArray());
                InfoTextBox.Text += "\nSession key = " + new BigInteger (result);
                FROG.Key = result;
                FROG.SetRoundsKeys();

                // закрываем сокет
                handler.Shutdown(SocketShutdown.Both);
                handler.Close();

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
            else if(CFB.IsChecked == true) Encryptor.encryptionMode = Encryptor.EncryptionMode.CFB;
            else if(OFB.IsChecked == true) Encryptor.encryptionMode = Encryptor.EncryptionMode.OFB;
        }


        private void EncryptClick(object sender, RoutedEventArgs e)
        {
            try
            {
                Encryptor.EncryptFile(_InputFile, _OutputFile, progressBar);
                InfoTextBox.Text += "\nEncryption file = " + _InputFile + "->" + Encryptor.encryptionMode;
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
                InfoTextBox.Text += "\nDecryption file = " + _InputFile + "->" +Encryptor.encryptionMode;
            }
            catch
            {
                InfoTextBox.Text += "\n--->" + DateTime.Now + ": " + "Ошибка в открытии выходного файла";
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
