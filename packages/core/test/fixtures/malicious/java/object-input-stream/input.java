// Defanged: ObjectInputStream.readObject on a network-sourced stream.
// The canonical Java deserialization-RCE shape.
import java.io.ObjectInputStream;
import java.net.Socket;

public class Loader {
    public Object load(Socket s) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(s.getInputStream());
        return ois.readObject();
    }
}
