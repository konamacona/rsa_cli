/**
 * File:    Program.cs
 * Author:  Mitchell Keenan - 10011960
 * Date:    November 25th, 2015
 * Class:   COMP 3343 Data Communications
 * Description: Implements the RSA algorithms for key generation, encryption,
 *      and decryption as well as a simple command-line interface for using 
 *      these functions.
 */

using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;

//Because of issues with my laptop I had to hide the BigInteger in defines...
#if DNX451
using System.Security.Cryptography;
using System.Numerics;

namespace RSA
{
    /// <summary>
    /// A class which holds the various keys generated with the RSA algorithm
    /// </summary>
    public class KeySet
    {
        public BigInteger n; //Modulus
        public BigInteger e; //Public Key Exponent
        public BigInteger d; //Private Key Exponent

        public KeySet(BigInteger n, BigInteger e, BigInteger d)
        {
            this.n = n;
            this.e = e;
            this.d = d;
        }

        public override string ToString()
        {
            return "{ mod: " + n + ", public: " + e + ", private: " + d + " }";
        }
    }

    public class Program
    {
        static bool DEBUG = false;
        static string HELP_HEADER = "RSA Implementation - Mitch Keenan:";
        static string E_HELP = "Encoding Mode: (-e / -encode)" +
                    "\n\tUse 'RSA -e <modulus> <public key>' to encrypt" +
                    "\n\tBest used by piping in an input file, and piping" +
                    "\n\tthe result to an output file";
        static string D_HELP = "Decoding Mode: (-d / -decode)" +
                    "\n\tUse 'RSA -d <modulus> <private key>' to decrypt" +
                    "\n\tBest used by piping in an input file, and piping" +
                    "\n\tthe result to an output file";
        static string G_HELP = "Generation Mode: (-g / -generate)" +
                    "\n\tUse 'RSA -g <key bit length>' to generate keys";
        static string T_HELP = "Test Mode: (-t)" +
                    "\n\tTests the functions of the program";

        /// <summary>
        /// Main programs, directs program flow
        /// </summary>
        /// <param name="args">The command line args tokenized</param>
        public void Main(string[] args)
        {
            if (DEBUG)
                args = new string[] { "-t" };

            bool modeFound = false;
            for (int i = 0; i < args.Length; i++)
            {
                if(args[i] == "-encode" || args[i] == "-e")
                {
                    encodingMode(args.Skip(i + 1).ToArray());
                    modeFound = true;
                }
                else if (args[i] == "-decode" || args[i] == "-d")
                {
                    decodingMode(args.Skip(i + 1).ToArray());
                    modeFound = true;
                }
                else if (args[i] == "-g" || args[i] == "-generate")
                {
                    generationMode(args.Skip(i + 1).ToArray());
                    modeFound = true;
                }
                else if (args[i] == "-t" || args[i] == "-test")
                {
                    modeFound = true;
                    int BL = 16;
                    Console.WriteLine("Testing with key length = " + BL);
                    var keys = GenerateKeys(BL);
                    Console.WriteLine("Generated Keys: \n\t" + keys);
                    var m = "All your base are belong to us!";
                    Console.WriteLine("Test Message:\n\t" + m);
                    var e = Encode_String(m, keys.n, keys.e);
                    Console.WriteLine("Encoded Message: \n" + e);
                    var d = Decode_String(e, keys.n, keys.d);
                    Console.WriteLine("Decoded Message: \n\t" + d);

                    WaitToQuit();
                }
                if (modeFound)
                    break;
            }

            if(modeFound)
            {
                return;
            }

            Console.WriteLine(  HELP_HEADER + "\n" +
                                E_HELP + "\n" + 
                                D_HELP + "\n" + 
                                G_HELP + "\n" + 
                                T_HELP);
            WaitToQuit();
        }

        /// <summary>
        /// Gets as many lines as it can from input before encountering 'exit'
        /// at the start of a line
        /// </summary>
        /// <returns>Returns all lines of input concatenated</returns>
        public string getConsoleInput()
        {
            var s = "";
            var t = "";
            while (true)
            {
                t = Console.ReadLine();
                if (t == null || t.StartsWith("exit"))
                    break;
                else
                    s += t;
            }
            return s;
        }

        public void encodingMode(string[] args)
        {
            if(args.Length != 2)
            {
                Console.WriteLine(E_HELP);
                return;
            }

            BigInteger n, p;
            if(!BigInteger.TryParse(args[0], out n) || 
               !BigInteger.TryParse(args[1], out p))
            {
                Console.WriteLine("Unable to parse values!");
                return;
            }
            var message = getConsoleInput();
            Console.WriteLine(Encode_String(message, n, p));
        }

        public void decodingMode(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine(D_HELP);
                return;
            }

            BigInteger n, p;
            if (!BigInteger.TryParse(args[0], out n) ||
               !BigInteger.TryParse(args[1], out p))
            {
                Console.WriteLine("Unable to parse values!");
                return;
            }
            var message = getConsoleInput();
            Console.WriteLine(Decode_String(message, n, p));
        }

        public void generationMode(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine(G_HELP);
                return;
            }
            int bit_length;
            if (int.TryParse(args[0], out bit_length) && 
                bit_length >= 8 && 
                bit_length <= 24)
                Console.WriteLine(GenerateKeys(bit_length));
            else
                Console.WriteLine("Please enter a valid integer bit_length " + 
                    "between 8 and 24");
        }

        /// <summary>
        /// Utility function which waits for user to hit enter before quiting 
        /// the command window
        /// </summary>
        public void WaitToQuit()
        {
            Console.WriteLine("Hit Enter to quit");
            Console.ReadLine();
        }

#region stringEncoding

        public string Encode_String(string message, BigInteger n, BigInteger e)
        {
            string result = "";
            foreach(var b in Encoding.UTF8.GetBytes(message))
            {
                var ba = new byte[1] { b };
                result += Encode(new BigInteger(ba), n, e).ToString() + ' ';
            }
            return result.TrimEnd(' ');
        }

        public string Decode_String(string message, BigInteger n, BigInteger d)
        {
            var words = message.Split(' ');
            List<byte> bytes = new List<byte>();
            foreach(var w in words)
            {
                byte b;
                BigInteger bi;
                if(!BigInteger.TryParse(w, out bi))
                {
                    Console.WriteLine("Unable to parse message!");
                    return "";
                }
                var db = Decode(bi, n, d);
                if (!byte.TryParse(db.ToString(), out b))
                {
                    Console.WriteLine("Unable to decode message!");
                    return "";
                }
                bytes.Add(b);
            }
            return Encoding.UTF8.GetString(bytes.ToArray());
        }

#endregion

#region primaryRSAfunctionality

        /// <summary>
        /// Encodes a BigInteger using the given modulus and public key
        /// </summary>
        /// <param name="message"></param>
        /// <param name="n">The modulus value as a BigInteger</param>
        /// <param name="e">The public key value as a BigInteger</param>
        /// <returns>The encoded message as a BigInteger</returns>
        public BigInteger Encode(BigInteger message, BigInteger n, BigInteger e)
        {
            return ModExp(message, e, n);
        }

        /// <summary>
        /// Decodes a bigInteger using the given modulus and private key
        /// </summary>
        /// <param name="encoded">The encoded bigInteger</param>
        /// <param name="n">The modulus value as BigInteger</param>
        /// <param name="d">The private key as BigInteger</param>
        /// <returns>The decoded message as a BigInteger</returns>
        public BigInteger Decode(BigInteger encoded, BigInteger n, BigInteger d)
        {
            return ModExp(encoded, d, n);
        }

        /// <summary>
        /// Generates the actual key pairs for RSA encryption
        /// </summary>
        /// <param name="bit_length">
        /// The bit length for the keys
        /// </param>
        /// <returns>
        /// A KeySet which contains the information for the public and private 
        /// key.
        /// </returns>
        public KeySet GenerateKeys(int bit_length)
        {
            BigInteger n, p, q, t, e, d;

            //n should be a bit_length bits BigInteger, lets setup a max and min
            BigInteger max_n = Power(2, bit_length) - 1;
            BigInteger min_n = Power(2, bit_length - 1);

            //The encryption will be strongest if the prime numbers are very
            //similar in bit length, here we use half the specified bit length
            //for n plus or minus 2
            BigInteger p_min = Power(2, (bit_length / 2) - 1); 
            BigInteger p_max = Power(2, (bit_length / 2) + 1);
            Tuple<BigInteger, BigInteger> primes = 
                Random_Primes(p_min, p_max, min_n, max_n);

            p = primes.Item1;
            q = primes.Item2;

            if (p == -1 || q == -1)
            {
                Console.WriteLine("No Primes available between " + 
                                    p_min + 
                                    " and " +
                                    p_max
                );
                return null;
            }

            n = p * q;
            t = Totient(n, p, q);

            do
            {
                e = RandomBigInt(bit_length);
            } while (e < 0 || e > t || GCD(e, t) != 1);

            d = ModInv(e, t);

            if(DEBUG)
                Console.WriteLine("p: " + p +
                            "\nq: " + q +
                            "\nq: " + t
                            );

            return new KeySet(n, e, d);

        }
#endregion

#region utility_math

        /// <summary>
        /// Returns b^e by method of exponentiation by squaring
        /// See: https://en.wikipedia.org/wiki/Exponentiation_by_squaring
        /// </summary>
        /// <param name="b">a BigInteger base b</param>
        /// <param name="e">a BigInteger exponent >= 0, e</param>
        /// <returns>b^e</returns>
        public BigInteger Power(BigInteger b, BigInteger e)
        {
            if (e < 0)
                return -1; //Int so fail
            else if (e == 0)
                return 1;
            else if (e == 1)
                return b;
            //else if (BigInteger.BitwiseAnd(e, 1) == 0) // e is even
            else if (e % 2 == 0)
                return Power(b * b, e / 2);
            else //e is odd
                return b * Power(b * b, (e - 1) / 2);
        }

        /// <summary>
        /// Returns (b^e) mod m through modular exponentiaion particularly the 
        /// Right-to-left binary method, see:
        ///     https://en.wikipedia.org/wiki/Modular_exponentiation
        /// </summary>
        /// <param name="b">A BigInteger base</param>
        /// <param name="e">A BigInteger exponent</param>
        /// <param name="m">A BigInteger modulus</param>
        /// <returns>(b^e) mod m as a BigInteger</returns>
        public BigInteger ModExp(BigInteger b, BigInteger e, BigInteger m)
        {
            if (m == 1)
                return 0;
            BigInteger result = 1;
            b = b % m;
            while (e > 0)
            {
                if (e % 2 == 1)
                    result = (result * b) % m;
                e >>= 1;
                b = (b * b) % m;
            }
            return result;
        }

        /// <summary>
        /// Returns the modular multiplicative inverse of a modulo b, where a
        /// and b are co-prime
        /// 
        /// Code adapted from 
        ///     "http://rosettacode.org/wiki/Modular_inverse#C.2B.2B"
        /// </summary>
        /// <param name="a">A BigInteger value co-prime with b</param>
        /// <param name="b">A BigInteger value co-prime with a</param>
        /// <returns>The modular multiplicative inverse for a and b</returns>
        public BigInteger ModInv(BigInteger a, BigInteger b)
        {
            BigInteger t, q;
            BigInteger b0 = b;
            BigInteger x0 = BigInteger.Zero;
            BigInteger x1 = BigInteger.One;
            while (a > BigInteger.One)
            {
                q = a / b;
                t = b;
                b = a % b;
                a = t;
                t = x0;
                x0 = x1 - q * x0;
                x1 = t;
            }
            if (x1 < BigInteger.Zero)
                x1 += b0;
            return x1;
        }

        /// <summary>
        /// Calculates the greatest common denominator of a and b using Euclid's
        /// Algorithm
        /// </summary>
        /// <param name="a">A BigInteger value</param>
        /// <param name="b">A BigInteger value</param>
        /// <returns>
        /// The greatest common denominator of a and b as a BigInteger
        /// </returns>
        public BigInteger GCD(BigInteger a, BigInteger b)
        {
            if (b == 0)
                return a;
            //else
            return GCD(b, a % b);
        }

        /// <summary>
        /// Returns the totient of n, using p and q
        /// </summary>
        /// <param name="n">n is the quotient of p and q</param>
        /// <param name="p">p is a prime factor of n</param>
        /// <param name="q">q is a prime factor of n</param>
        /// <returns>Totient(n) as a BigInteger</returns>
        public BigInteger Totient(BigInteger n, BigInteger p, BigInteger q)
        {
            /*
             * While totient(pq) is typically written (p - 1)(q - 1), it is
             * better to expand this to (pq - p - q + 1) as we already know 
             * that pq = n.
             */

            return n - p - q + 1;
        }


#endregion

#region prime_gen

        /// <summary>
        /// Returns two random prime numbers between min and max, which when 
        /// multiplied fall in the range m_min, m_max
        /// </summary>
        /// <param name="min">
        /// An BigInteger Max value for prime generation
        /// </param>
        /// <param name="max">
        /// An BigInteger Min value for prime generation
        /// </param>
        /// <returns>
        /// An BigInteger Tuple of two random primes between min and max, 
        /// a tuple of -1's if none are found
        /// </returns>
        public Tuple<BigInteger, BigInteger> Random_Primes(BigInteger min, 
                                                           BigInteger max, 
                                                           BigInteger m_min,
                                                           BigInteger m_max)
        {
            var primes = Prime_Sieve(min, max);
            var rnd = new Random();
            BigInteger p1 = new BigInteger(-1);
            BigInteger p2 = new BigInteger(-1); ;
            if(primes.Count > 1)
            {
                BigInteger n;
                int r = rnd.Next(0, primes.Count);
                p1 = primes.ElementAt(r);
                primes.RemoveAt(r);
                do
                {
                    r = rnd.Next(0, primes.Count);
                    p2 = primes.ElementAt(r);
                    primes.RemoveAt(r);
                    n = p1 * p2;
                } while (primes.Count > 0 && (n < m_min || n > m_max));
            }

            return new Tuple<BigInteger, BigInteger>(p1, p2);
        }

        /// <summary>
        /// Generates a list of primes between the values min and max using the
        /// sieve of eratosthenes method.
        /// </summary>
        /// <param name="min">
        /// A BigInteger Max value for prime generation
        /// </param>
        /// <param name="max">
        /// A BigInteger Min value for prime generation
        /// </param>
        /// <returns>
        /// An BigInteger List of primes between min and max, list can be empty
        /// </returns>
        public List<BigInteger> Prime_Sieve(BigInteger min, BigInteger max)
        {
            List<BigInteger> primes = new List<BigInteger>();

            //Don't bother if the bounds are backwards
            if (min > max)
                return primes;

            primes.Add(2);

            for(BigInteger i = 2; i < max; i++)
            {
                if (!primes.Exists(p => i % p == 0))
                {
                    primes.Add(i);
                }
            }

            return primes.Where(p => p > min).ToList();
        }
#endregion

#region random_gen

        //http://stackoverflow.com/a/2965724
        /// <summary>
        /// Generates a random bigInteger with bit_length bits, uses Crypt safe
        /// RNG if available/
        /// </summary>
        /// <param name="bit_length">Bit length for result as int</param>
        /// <returns>A random BigInteger of size bit_length</returns>
        public BigInteger RandomBigInt(int bit_length)
        {
            byte[] bytes = new byte[bit_length / 8];

            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(bytes);

            return new BigInteger(bytes);
        }
#endregion
    }
}

#endif
