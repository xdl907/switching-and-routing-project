from mininet.topo import Topo

#The script implements a complete mesh mininet topology according to some defined parameters
#POSSIBLE IMPROVEMENTS: partially connected mesh implementation via a random number of links for each switch

class mplsmesh(Topo):

    def __init__(self):

        Topo.__init__(self)
    	
    	#Network parameters
    	n_sw=4 #switches
    	n_hostxsw=1 #hosts per switch
        links=[]

    	#Switch and host declarations
    	for i in range(1,n_sw+1):
    		switch=self.addSwitch("s%s" %i)
    		for j in range(1,n_hostxsw+1):
    			host=self.addHost("h%s" %(j+((i-1)*n_hostxsw)))
    			self.addLink(host,switch)

    	#Switch to switch link generation
        for sw1 in range(1,n_sw+1):
            for sw2 in range(1,n_sw+1):
                if sw2 != sw1:
                    links.append((sw1,sw2))
                    self.addLink("s%s" %sw1 , "s%s" %sw2)
         
        
topos = {'mplsmesh': (lambda: mplsmesh())}

#The script is launched with the command
#sudo mn --custom mininet/custom/meshtopology.py --mac --topo mplsmesh --controller=remote --switch ovs,protocols=OpenFlow13