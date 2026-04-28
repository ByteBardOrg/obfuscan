// Defanged: BinaryFormatter.Deserialize on attacker-controlled input.
// BinaryFormatter is the canonical .NET deserialization-RCE primitive.
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

public class Loader
{
    public static object Load(Stream input)
    {
        var fmt = new BinaryFormatter();
        return fmt.Deserialize(input);
    }
}
