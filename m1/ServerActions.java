import java.lang.Thread;
import java.net.Socket;
import java.io.OutputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import com.google.gson.*;
import com.google.gson.stream.*;

class ServerActions implements Runnable {

ClientDescription me;
boolean registered = false;

Socket client;
JsonReader in;
OutputStream out;
ServerControl registry;

ServerActions ( Socket c, ServerControl r )
{
    client = c;
    registry = r;

    try {
	in = new JsonReader( new InputStreamReader ( c.getInputStream(), "UTF-8") );
	out = c.getOutputStream();
    } catch ( Exception e ) {
        System.err.print( "Cannot use client socket: " + e );
	Thread.currentThread().interrupt();
    }
}

JsonObject
readCommand ()
{
    try {
	JsonElement data = new JsonParser().parse( in );
	if (data.isJsonObject()) {
	    return data.getAsJsonObject();
	}
        System.err.print ( "Error while reading command from socket (not a JSON object), connection will be shutdown\n" );
	return null;
    } catch (Exception e) {
        System.err.print ( "Error while reading JSON command from socket, connection will be shutdown\n" );
	return null;
    }

}

void
sendResult ( String type, String extra )
{
     String msg = "{\"type\":\"" + type + "\"";

     if (extra != null) {
         msg += "," + extra;
     }
     msg += "}\n";

     try {
	 System.out.print( "Send result: " + msg );
	 out.write ( msg.getBytes( StandardCharsets.UTF_8 ) );
     } catch (Exception e ) {}
}

void
executeCommand ( JsonObject data )
{
     JsonElement cmd = data.get( "type" );

     if (cmd == null) {
         System.err.println ( "Invalid command in message: " + data );
	 return;
     }

     if (cmd.getAsString().equals( "connect" )) {
         JsonElement id = data.get( "id" );
	 if (id == null) {
	     System.err.print ( "No \"id\" field in \"connect\" command: " + data );
	     sendResult( "unknown", null );
	     return;
	 }

         JsonElement phase = data.get( "phase" );
	 if (phase == null) {
	     System.err.print ( "No \"phase\" field in \"connect\" command: " + data );
	     sendResult( "unknown", null );
	     return;
	 }

	 if (phase.getAsInt() == 1) {
	     if (registered || registry.clientExists( id.getAsString() )) {
		 System.err.println ( "Client is already registered: " + data );
		 // send error
		 if (registered) {
		     sendResult( "connect", "\"phase\"=\"0\", \"data\"=\"error: reconnection\"" );
		 }
		 else {
		     sendResult( "connect", "\"phase\"=\"0\", \"data\"=\"error: id already in use\"" );
		 }
		 return;
	     }
	 }
	 else {
		 // send error
		 sendResult( "connect", "\"phase\"=\"0\", \"data\"=\"error: not implemented\"" );
	 }

 
	 data.remove ( "type" );
	 me = registry.addClient( id.getAsString(), data, out );
	 registered = true;

	 sendResult( "connect", "\"phase\"=\"2\", \"data\"=\"ok\"" );
	 return;
     }
     else if (cmd.getAsString().equals( "secure" )) {
         JsonObject payload = data.getAsJsonObject( "payload" );
         JsonElement innerCmd = (payload == null) ? null : payload.get( "type" );

	 if (innerCmd == null) {
	     // send error
	     sendResult( "secure", "\"payload\"=\"error: type field missing\"" );
	     return;
	 }

	 if (innerCmd.getAsString().equals( "list" )) {
	     String list = registry.listClients( null );
	     String response;

	     if (list == null) {
		 response = "\"payload\"={\"type\"=\"list\", \"data\"=[]}";
	     }
	     else {
		 response = "\"payload\"={\"type\"=\"list\", \"data\"=" + list + "}";
	     }
	     sendResult( "secure", response );
	     return;
	 }
	 else if (innerCmd.getAsString().equals( "client-connect" ) ||
		    innerCmd.getAsString().equals( "client-disconnect" ) ||
		    innerCmd.getAsString().equals( "client-com" ) ||
		    innerCmd.getAsString().equals( "ack" )) {
	     JsonElement id = data.get( "dst" );

	     if (id == null) {
		 // send error
		 sendResult( "secure", "\"payload\"=\"error: dst field missing\"" );
		 return;
	     }

	     // src should be checked as well ... 

	     OutputStream target = registry.getOutputStream( id.getAsString() );

	     if (target == null) {
		 // send error
		 sendResult( "secure", "\"payload\"=\"error: dst not found\"" );
		 return;
	     }

	     try {
		 target.write( data.toString().getBytes( StandardCharsets.UTF_8 ) );
	     } catch (Exception e) {}
	 }
	 else {
	     // send error
	     sendResult( "secure", "\"payload\"=\"error: wrong type\"" );
	     return;
	 }

	 return;
     }
     else {
         System.err.println ( "Invalid command in message: " + data );
	 return;
     }
}

public void
run ()
{
    while (true) {
        JsonObject cmd = readCommand();
	if (cmd == null) {
	    if (registered) {
	        registry.removeClient( me.id );
		try {
		    client.close();
		} catch (Exception e) {}
		return;
	    }
	}
	executeCommand ( cmd );
    }

}

}

