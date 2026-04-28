// Defanged: Runtime.exec with a string built from untrusted input.
public class Cmd {
    public void run(String name) throws Exception {
        Runtime.getRuntime().exec("ls " + name);
    }
}
