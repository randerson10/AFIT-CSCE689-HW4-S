#ifndef REPLSERVER_H
#define REPLSERVER_H

#include <map>
#include <set>
#include <memory>
#include "QueueMgr.h"
#include "DronePlotDB.h"

/***************************************************************************************
 * ReplServer - class that manages replication between servers. The data is automatically
 *              sent to the _plotdb and the replicate method loops, handling replication
 *              until _shutdown is set to true. The QueueMgr object does the majority of
 *              the communications. This object simply runs management loops and should
 *              do deconfliction of nodes
 *
 ***************************************************************************************/
class ReplServer 
{
public:
   ReplServer(DronePlotDB &plotdb, const char *ip_addr, unsigned short port,
                              float _time_mult = 1.0, unsigned int verbosity = 1);
   ReplServer(DronePlotDB &plotdb, float _time_mult = 1.0);
   virtual ~ReplServer();

   // Main replication loop, continues until _shutdown is set
   void replicate(const char *ip_addr, unsigned short port);
   void replicate();
  
   // Call this to shutdown the loop 
   void shutdown();

   // An adjusted time that accounts for "time_mult", which speeds up the clock. Any
   // attempts to check "simulator time" should use this function
   time_t getAdjustedTime();

private:

   void addReplDronePlots(std::vector<uint8_t> &data);
   void addSingleDronePlot(std::vector<uint8_t> &data);
   
   //removes duplicate plot points from the database
   void removeDuplicatePlots();
   //checks the database to try to determine the timeskew of any node in this simulation
   void checkDBForTimeOffset();
   //updates the database by correcting node times based off the timeskew of that node
   void correctTimeSkew();
   //returns the authority(coordinator) to which nodes can compare their times with
   unsigned int getAuthority();

   unsigned int queueNewPlots();

   QueueMgr _queue;    

   // Holds our drone plot information
   DronePlotDB &_plotdb;

   bool _shutdown;

   // How fast to run the system clock - 1.0 = normal speed, 2.0 = 2x as fast
   float _time_mult;

   // System clock time of when the server started
   time_t _start_time;

   // When the last replication happened so we can know when to do another one
   time_t _last_repl;

   // How much to spam stdout with server status
   unsigned int _verbosity;

   // Used to bind the server
   std::string _ip_addr;
   unsigned short _port;

   //the node ids of the nodes in this simulation
   std::set<unsigned int> _node_ids;
   //this map stores the node id and a time offset
   std::map<unsigned int, int> _offsets;
   //bool representing if any timeskew has been found in the simulation
   bool _foundTimeOffset = false;
   //bool representing if the timeskew for all nodes in this simulation have been found
   bool _foundAllTimeOffsets = false;
};


#endif
