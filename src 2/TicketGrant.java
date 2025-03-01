import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class TicketGrant {
    private Map<String, Ticket> ticketStore;

    public TicketGrant() {
        this.ticketStore = new HashMap<>();
    }

    public Ticket generateTicket(String clientId, String serverId, int validityMinutes) {
        // Generate a random session key
        String sessionKey = UUID.randomUUID().toString();

        // Create a new ticket
        Ticket ticket = new Ticket(sessionKey, clientId, serverId, validityMinutes);

        // Store the ticket using a unique identifier
        String ticketId = UUID.randomUUID().toString();
        ticketStore.put(ticketId, ticket);

        System.out.println("Ticket generated successfully for Client: " + clientId + " and Server: " + serverId);
        return ticket;
    }

    public boolean validateTicket(String clientId, String serverId, Ticket ticket) {
        if (ticket == null || ticket.isExpired()) {
            System.err.println("Ticket is invalid or expired for Client: " + clientId + " and Server: " + serverId);
            return false;
        }
        System.out.println("Ticket validated successfully for Client: " + clientId + " and Server: " + serverId);
        return true;
    }

    public void removeExpiredTickets() {
        ticketStore.entrySet().removeIf(entry -> entry.getValue().isExpired());
        System.out.println("Expired tickets removed.");
    }

    public static void main(String[] args) {
        TicketGrant ticketGrant = new TicketGrant();

        // Generate a ticket
        Ticket ticket = ticketGrant.generateTicket("Client1", "Server1", 5);
        ticket.displayTicketDetails();

        // Validate the ticket
        boolean isValid = ticketGrant.validateTicket("Client1", "Server1", ticket);
        System.out.println("Is ticket valid? " + isValid);

        // Simulate ticket expiration cleanup
        ticketGrant.removeExpiredTickets();
    }
}