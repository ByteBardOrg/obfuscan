// Defanged: System.Convert.FromBase64String -> Assembly.Load. The decoded
// bytes are NOT a real assembly here; the shape is what matters.
using System;
using System.Reflection;

public class Loader
{
    public void Run(string blob)
    {
        byte[] bytes = Convert.FromBase64String(blob);
        Assembly asm = Assembly.Load(bytes);
        // Real attacks would invoke a method on `asm` next.
    }
}
