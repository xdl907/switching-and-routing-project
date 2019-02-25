from mininet.topo import Topo


class mpls(Topo):

    def build(self):

        #Dichiarazione degli hosts
        
        host1 = self.addHost('h1')
        host2 = self.addHost('h2')
        

        #Dichiarazione degli switches e dei loadbalancer 

        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')
        switch3 = self.addSwitch('s3')
        switch4 = self.addSwitch('s4')


        
        #Creazione dei link host - switch  
        
        self.addLink(host1, switch1, port1=1,port2=1)
        self.addLink(host2, switch2, port1=1,port2=1)
        self.addLink(switch1, switch3, port1=2,port2=1)
        self.addLink(switch1, switch4, port1=3,port2=1)
        self.addLink(switch2, switch3, port1=2,port2=2)
        self.addLink(switch2, switch4, port1=3,port2=2)
        

topos = {'mpls': (lambda: mpls())}

#sudo mn --controller=remote --custom topology.py --topo mpls