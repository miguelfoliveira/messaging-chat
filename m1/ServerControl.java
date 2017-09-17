import java.io.OutputStream;
import java.util.concurrent.ConcurrentSkipListSet;
import com.google.gson.*;

class ServerControl {
ConcurrentSkipListSet<ClientDescription> clients = null;

ServerControl ()
{
    clients = new ConcurrentSkipListSet<ClientDescription>();
}

synchronized boolean
clientExists ( String id )
{
    return clients.contains( new ClientDescription( id, null, null ) );
}

synchronized JsonElement
getClient ( String id )
{
    for (ClientDescription c: clients) {
        if (c.id.equals( id )) {
	    return c.description;
	}
    }

    return null;
}

synchronized ClientDescription
addClient ( String id, JsonElement description, OutputStream out )
{
    System.out.println ( "Added client \"" + id + "\": " + description );
    ClientDescription client = new ClientDescription( id, description, out );
    clients.add( client );
    return client;
}

synchronized boolean
removeClient ( String id )
{
    System.out.println ( "Removed client \"" + id + "\"" );
    return clients.remove( new ClientDescription( id, null, null ) );
}

synchronized String
listClients ( String id )
{
    if (id == null) {
	System.out.println( "Looking for all connected clients" );
    }
    else {
	System.out.println( "Looking for \"" + id + "\"" );
    }

    if (id != null) {
	JsonElement client = getClient( id );
	if (client != null) {
	    return "[" + client + "]";
	}
	return null;
    }
    else {
	String list = null;
	for (ClientDescription c: clients) {
	    if (list == null) {
		list = "[" + c.description; 
	    }
	    else {
		list += "," + c.description; 
	    }
	}
	
	if (list == null) {
	    list = "[]";
	}
	else {
	    list += "]";
	}
        return list;
    }
}

synchronized OutputStream
getClientStream ( String id )
{
    for (ClientDescription c: clients) {
        if (c.id.equals( id )) {
	    return c.out;
	}
    }

    return null;
}

synchronized OutputStream
getOutputStream ( String id )
{
    System.out.println( "Looking for \"" + id + "\"" );

    return getClientStream( id );
}

}
