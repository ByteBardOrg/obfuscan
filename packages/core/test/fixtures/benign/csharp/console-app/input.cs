using System;
using System.Linq;

public class Program
{
    public static void Main(string[] args)
    {
        var nums = args.Select(int.Parse).ToArray();
        Console.WriteLine($"sum: {nums.Sum()}");
    }
}
