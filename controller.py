# Written by Tin Thurein
# It is configured with 5 hosts and 5 switches.

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Final (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

  def drop(self, packet, packet_in):
    msg = of.ofp_flow_mod()
    msg.match=of.ofp_match.from_packet(packet)
    msg.idle_timeout = 30
    msg.hard_timeout = 60
    msg.data = packet_in
    #no action = drop
    self.connection.send(msg)

  def forward(self,packet,packet_in, outport):
    msg = of.ofp_flow_mod()
    msg.match=of.ofp_match.from_packet(packet)
    msg.idle_timeout = 30
    msg.hard_timeout = 60
    msg.data = packet_in
    action = of.ofp_action_output(port= outport)
    msg.actions.append(action)
    self.connection.send(msg)

  def flood(self, packet, packet_in):
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match.from_packet(packet)
    msg.idle_timeout = 30
    msg.hard_timeout = 60
    action = of.ofp_action_output(port=of.OFPP_FLOOD)
    msg.actions.append(action)
    #msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    msg.data = packet_in
    self.connection.send(msg)

  def do_final (self, packet, packet_in, port_on_switch, switch_id):
    # This is where you'll put your code. The following modifications have 
    # been made from Lab 3:
    #   - port_on_switch: represents the port that the packet was received on.
    #   - switch_id represents the id of the switch that received the packet.
    #      (for example, s1 would have switch_id == 1, s2 would have switch_id == 2, etc...)
    # You should use these to determine where a packet came from. To figure out where a packet 
    # is going, you can use the IP header information.
    
    #from h4, no ICMP to any
    #No IP to server
    #IP to h1,h2,h3
    #no iperf between h4 and h5
    #steps:
    #1: if found non IP, then flood to everywhere
    #2: else if: from switch1: OK
    #2: else if: from switch4: NO IP to server, but IP to h1-h3, and no ICMP to any
    #added
    ip = packet.find('ipv4')
    icmp = packet.find('icmp')
    tcp = packet.find('tcp')
    
    if ip is None:
        # not IP packets then flood
        self.forward(packet,packet_in, of.OFPP_FLOOD)
        return
    
    if switch_id is 1:

        #logic:
        ##1: from h2,h3 or h5 to h1, forward
        ##2: from h1 to h2, h3 or h5, forward
        ##3: from h4 to h1 w/ ip, forward
        ##4: from h1 to h4 w/ ip, forward
        ##5: from h4 to h1 w/ icmp, drop
        ##6: from h1 to h4 w/ icmp, drop

        print "at s1"

        ip = packet.find('ipv4')
        icmp = packet.find('icmp')
        tcp = packet.find('tcp')

        ##1: from h2,h3 or h5 to h1, forward 
        if ip.srcip != "123.45.67.89" and ip.dstip == "10.1.1.10":
            self.forward(packet, packet_in, 8) #port 8 for s1 to h1
            print "#1: from h2,h3 or h5 to h1, forward"

        ##2: from h1 to h2, h3 or h5, forward
        elif ip.srcip == "10.1.1.10" and ip.dstip != "123.45.67.89":
            self.forward(packet, packet_in, 1) #port 1 for h1 to s1
            print "#2: from h1 to h2, h3 or h5, forward"
    
        ##3: from h4 to h1 w/ ip, forward
        elif ip.srcip == "123.45.67.89" and packet.find ('ipv4') is not None and ip.dstip == "10.1.1.10":
            self.forward(packet,packet_in, 8)
            print "#3: from h4 to h1 w/ ip, forward"

        ##4: from h1 to h4 w/ ip, forward
        elif ip.srcip == "10.1.1.10" and packet.find ('ipv4') is not None and ip.dstip == "123.45.67.89":
            self.forward(packet,packet_in, 1)
            print "#4: from h1 to h4 w/ ip, forward"

        ##5: from h4 to h1 w/ icmp, drop
        elif ip.srcip == "123.45.67.89" and packet.find('icmp') is not None and ip.dstip == "10.1.1.10":
            self.drop(packet,packet_in)
            print "#5: from h4 to h1 w/ icmp, drop"

        ##6: from h1 to h4 w/ icmp, drop
        elif ip.srcip == "10.1.1.10" and packet.find('icmp') is not None and ip.dstip == "123.45.67.89":
            self.drop(packet,packet_in)
            print "#6: from h1 to h4 w/ icmp, drop"

        

        

    if switch_id is 2:
        #logic:
        ##1: from h1,h3 or h5 to h2, forward
        ##2: from h2 to h1, h3 or h5, forward
        ##3: from h4 to h2 w/ ip, forward
        ##4: from h2 to h4 w/ ip, forward
        ##5: from h4 to h2 w/ icmp, drop
        ##6: from h2 to h4 w/ icmp, drop

        print "at s2"
        
        ##1: from h1,h3 or h5 to h2, forward
        if ip.srcip != "123.45.67.89" and ip.dstip == "10.2.2.20":
            self.forward(packet, packet_in, 8) #port 8 for s1 to h2
            print"#1: from h1,h3 or h5 to h2, forward"

        ##2: from h2 to h1, h3 or h5, forward
        elif ip.srcip == "10.2.2.20" and ip.dstip != "123.45.67.89":
            self.forward(packet, packet_in, 2) #port 1 for h1 to s2
            print "#2: from h2 to h1, h3 or h5, forward"
    
        ##3: from h4 to h2 w/ ip, forward
        elif ip.srcip == "123.45.67.89" and packet.find ('ipv4') is not None and ip.dstip == "10.2.2.20":
            self.forward(packet,packet_in, 8)
            print "#3: from h4 to h2 w/ ip, forward"

        ##4: from h2 to h4 w/ ip, forward
        elif ip.srcip == "10.2.2.20" and packet.find ('ipv4') is not None and ip.dstip == "123.45.67.89":
            self.forward(packet,packet_in, 2)
            print "#4: from h2 to h4 w/ ip, forward"

        ##5: from h4 to h2 w/ icmp, drop
        elif ip.srcip == "123.45.67.89" and packet.find('icmp') is not None and ip.dstip == "10.2.2.20":
            self.drop(packet,packet_in)
            print "#5: from h4 to h2 w/ icmp, drop"

        ##6: from h2 to h4 w/ icmp, drop
        elif ip.srcip == "10.2.2.20" and packet.find('icmp') is not None and ip.dstip == "123.45.67.89":
            self.drop(packet,packet_in)
            print "#6: from h2 to h4 w/ icmp, drop"

    if switch_id is 3:
        #logic:
        ##1: from h1,h2 or h5 to h3, forward
        ##2: from h3 to h1, h2 or h5, forward
        ##3: from h4 to h3 w/ ip, forward
        ##4: from h3 to h4 w/ ip, forward
        ##5: from h4 to h3 w/ icmp, drop
        ##6: from h3 to h4 w/ icmp, drop

        print "s3"
        
        ##1: from h1,h2 or h5 to h3, forward
        if ip.srcip != "123.45.67.89" and ip.dstip == "10.3.3.30":
            self.forward(packet, packet_in, 8) #port 8 for s1 to h1
            print "#1: from h1,h2 or h5 to h3, forward"


        ##2: from h3 to h1, h2 or h5, forward
        elif ip.srcip == "10.3.3.30" and ip.dstip != "123.45.67.89":
            self.forward(packet, packet_in, 3) #port 1 for h1 to s1
            print "#2: from h3 to h1, h2 or h5, forward"
    
        ##3: from h4 to h3 w/ ip, forward
        elif ip.srcip == "123.45.67.89" and packet.find ('ipv4') is not None and ip.dstip == "10.3.3.30":
            self.forward(packet,packet_in, 8)
            print "#3: from h4 to h3 w/ ip, forward"

        ##4: from h3 to h4 w/ ip, forward
        elif ip.srcip == "10.3.3.30" and packet.find ('ipv4') is not None and ip.dstip == "123.45.67.89":
            self.forward(packet,packet_in, 3)
            print "#4: from h3 to h4 w/ ip, forward"

        ##5: from h4 to h3 w/ icmp, drop
        elif ip.srcip == "123.45.67.89" and packet.find('icmp') is not None and ip.dstip == "10.3.3.30":
            self.drop(packet,packet_in)
            print "#5: from h4 to h3 w/ icmp, drop"

        ##6: from h3 to h4 w/ icmp, drop
        elif ip.srcip == "10.3.3.30" and packet.find('icmp') is not None and ip.dstip == "123.45.67.89":
            self.drop(packet,packet_in)
            print "#6: from h3 to h4 w/ icmp, drop"

    if switch_id is 4:
    #NO ICMP to any from h4
    #No IP to h5 (iperf shouldn't work)
    #IP to h1,h2,h3 (iperf should work)

    #logic:
    ##1: from h4, and icmp drop
    ##2: from h4 to h5 w/ ip, drop
    ##3: from h5 to h4 w/ ip, drop
    ##4: from h4 to h1, w/ ip, forward
    ##5: from h4 to h2, w/ ip, forward
    ##6: from h4 to h3, w/ ip, forward

    #
    ##7: from h1 to h2, w/ip, forward
    ##8: from h1 to h3, w/ip, forward
    ##9: from h1 to h4, w/ip, forward
    ##10: from h1 to h5, w/ip, forward

    ##11: from h2 to h1, w/ip, forward
    ##12: from h2 to h3, w/ip, forward
    ##13: from h2 to h4, w/ip, forward
    ##14: from h2 to h5, w/ip, forward

    ##15: from h3 to h1, w/ip, forward
    ##16: from h3 to h2, w/ip, forward
    ##17: from h3 to h4, w/ip, forward
    ##18: from h3 to h5, w/ip, forward

    ##19: from h5 to h1, w/ip, forward
    ##20: from h5 to h2, w/ip, forward
    ##21: from h5 to h3, w/ip, forward



        print "at s4"
        
        #1: if from h4, and icmp, drop
        if ip.srcip == "123.45.67.89" and packet.find('icmp') is not None:  
            self.drop(packet, packet_in)
            print "#1: if from h4, and icmp, drop"


        ##2: from h4 to h5 , drop
        elif ip.srcip == "123.45.67.89" and ip.dstip == "10.5.5.50":
            self.drop(packet, packet_in)
            print "#2: from h4 to h5, drop"


        ##3: from h5 to h4, drop
        elif ip.srcip == "10.5.5.50" and ip.dstip == "123.45.67.89":
            self.drop(packet, packet_in)
            print "#3: from h5 to h4, drop"

            
        ##4: from h4 to h1, w/ ip, forward
        elif ip.srcip == "123.45.67.89" and packet.find('ipv4') is not None and ip.dstip == "10.1.1.10":
            self.forward(packet, packet_in, 1)
            print "#4: from h4 to h1, w/ ip, forward"


        ##5: from h4 to h2, w/ ip, forward
        elif ip.srcip == "123.45.67.89" and packet.find('ipv4') is not None and ip.dstip == "10.2.2.20":
            self.forward(packet, packet_in, 2)
            print "#5: from h4 to h2, w/ ip, forward"


        ##6: from h4 to h3, w/ ip, forward
        elif ip.srcip == "123.45.67.89" and packet.find('ipv4') is not None and ip.dstip == "10.3.3.30":
            self.forward(packet, packet_in, 3)
            print "#6: from h4 to h3, w/ ip, forward"


       ##7: from h1 to h2, w/ip, forward
       #elif ip.srcip == "10.1.1.10" and packet.find('ipv4') is not None and ip.dstip == "10.2.2.20":
        elif ip.srcip == "10.1.1.10" and ip.dstip == "10.2.2.20":
            self.forward(packet, packet_in, 2)
            print "#7, at s4, from h1 to h2"

        ##8: from h1 to h3, w/ip, forward    
        elif ip.srcip == "10.1.1.10" and ip.dstip == "10.3.3.30":
            self.forward(packet, packet_in, 3)
            print "#8, at s4, from h1 to h3"

        ##9: from h1 to h4, w/ip, forward
        elif ip.srcip == "10.1.1.10" and packet.find('ipv4') is not None and ip.dstip == "123.45.67.89":
            self.forward(packet, packet_in, 8)
            print "#9, at s4, w/ ip from h1 to h4"

        ##10: from h1 to h5, w/ip, forward
        elif ip.srcip == "10.1.1.10" and ip.dstip == "10.5.5.50":
            self.forward(packet, packet_in, 4)
            print "#10, at s4, from h1 to h5"

        ##11: from h2 to h1, w/ip, forward
        elif ip.srcip == "10.2.2.20" and ip.dstip == "10.1.1.10":
            self.forward(packet, packet_in, 1)
            print "#11, at s4, from h2 to h1"

        ##12: from h2 to h3, w/ip, forward
        elif ip.srcip =="10.2.2.20" and ip.dstip =="10.3.3.30":	
            self.forward(packet, packet_in, 3)
            print "#12, at s4, from h2 to h3"

        ##13: from h2 to h4, w/ip, forward
        elif ip.srcip == "10.2.2.20" and packet.find('ipv4') is not None and ip.dstip == "123.45.67.89":
            self.forward(packet, packet_in, 8)
            print "#13, at s4, from h2 to h4, w/ ip"

        ##14: from h2 to h5, w/ip, forward
        elif ip.srcip == "10.2.2.20" and ip.dstip == "10.5.5.50":
            self.forward(packet, packet_in, 4)
            print "#14, at s4, from h2 to h5"

        ##15: from h3 to h1, w/ip, forward
        elif ip.srcip == "10.3.3.30" and ip.dstip == "10.1.1.10":
            self.forward(packet, packet_in, 1)
            print "#15, at s4, from h3 to h1"

        ##16: from h3 to h2, w/ip, forward
    	elif ip.srcip == "10.3.3.30" and ip.dstip == "10.2.2.20":
            self.forward(packet, packet_in, 2)
            print "#16, at s4, from h3 to h2"

        ##17: from h3 to h4, w/ip, forward
        elif ip.srcip == "10.3.3.30" and packet.find('ipv4') is not None and ip.dstip == "123.45.67.89":
            self.forward(packet, packet_in, 8)
            print "#17, at s4, from h3 to h4, w/ip"

        ##18: from h3 to h5, w/ip, forward
    	elif ip.srcip == "10.3.3.30" and ip.dstip == "10.5.5.50":
            self.forward(packet, packet_in, 4)
            print "#18, at s4, from h3 to h5"

        ##19: from h5 to h1, w/ip, forward
        elif ip.srcip == "10.5.5.50" and ip.dstip == "10.1.1.10":
            self.forward(packet, packet_in, 1)
            print "#19, at s5, from h3 to h1" 

        ##20: from h5 to h2, w/ip, forward
    	elif ip.srcip == "10.5.5.50" and ip.dstip == "10.2.2.20":
            self.forward(packet, packet_in, 2)
            print "#20, at s5, from h3 to h2" 

        ##21: from h5 to h3, w/ip, forward
    	elif ip.srcip == "10.5.5.50" and ip.dstip == "10.3.3.30":
            self.forward(packet, packet_in, 3)
            print "#21, at s5, from h3 to h3"




    if switch_id is 5:

        #logic:
        ##1: from h1,h2 or h3 to h5, forward
        ##2: from h5 to h1, h2 or h3, forward
        ##3: from h4 to h5 w/ ip, drop
        ##4: from h5 to h4 w/ ip, drop


        print "at s5"
        
        ##1: from h1,h2 or h3 to h5, forward
        if ip.srcip != "123.45.67.89" and ip.dstip == "10.5.5.50":
            self.forward(packet, packet_in, 8) #port 8 for s1 to h1
            print "#1: from h1,h2 or h3 to h5, forward"

        ##2: from h5 to h1, h2 or h3, forward
        elif ip.srcip == "10.5.5.50" and ip.dstip != "123.45.67.89":
            self.forward(packet, packet_in, 4) #port 1 for h1 to s1
            print "#2: from h5 to h1, h2 or h3, forward"
    
        ##3: from h4 to h5, drop
        elif ip.srcip == "123.45.67.89" and ip.dstip == "10.5.5.50":
            self.drop(packet, packet_in)
            print "#3: from h4 to h5, drop"

        ##4: from h5 to h4, drop
        elif ip.srcip == "10.5.5.50" and ip.dstip == "123.45.67.89":
            self.drop(packet,packet_in)
            print "#4: from h5 to h4, drop"


  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_final(packet, packet_in, event.port, event.dpid)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Final(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
