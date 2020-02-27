#include <iostream>
#include <exception>
#include <set>
#include "ReplServer.h"

const time_t secs_between_repl = 20;
const unsigned int max_servers = 10;

/*********************************************************************************************
 * ReplServer (constructor) - creates our ReplServer. Initializes:
 *
 *    verbosity - passes this value into QueueMgr and local, plus each connection
 *    _time_mult - how fast to run the simulation - 2.0 = 2x faster
 *    ip_addr - which ip address to bind the server to
 *    port - bind the server here
 *
 *********************************************************************************************/
ReplServer::ReplServer(DronePlotDB &plotdb, float time_mult)
                              :_queue(1),
                               _plotdb(plotdb),
                               _shutdown(false), 
                               _time_mult(time_mult),
                               _verbosity(1),
                               _ip_addr("127.0.0.1"),
                               _port(9999)
{
}

ReplServer::ReplServer(DronePlotDB &plotdb, const char *ip_addr, unsigned short port, float time_mult,
                                          unsigned int verbosity)
                                 :_queue(verbosity),
                                  _plotdb(plotdb),
                                  _shutdown(false), 
                                  _time_mult(time_mult), 
                                  _verbosity(verbosity),
                                  _ip_addr(ip_addr),
                                  _port(port)

{
}

ReplServer::~ReplServer() {

}


/**********************************************************************************************
 * getAdjustedTime - gets the time since the replication server started up in seconds, modified
 *                   by _time_mult to speed up or slow down
 **********************************************************************************************/

time_t ReplServer::getAdjustedTime() {
   return static_cast<time_t>((time(NULL) - _start_time) * _time_mult);
}

/**********************************************************************************************
 * replicate - the main function managing replication activities. Manages the QueueMgr and reads
 *             from the queue, deconflicting entries and populating the DronePlotDB object with
 *             replicated plot points.
 *
 *    Params:  ip_addr - the local IP address to bind the listening socket
 *             port - the port to bind the listening socket
 *             
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void ReplServer::replicate(const char *ip_addr, unsigned short port) {
   _ip_addr = ip_addr;
   _port = port;
   replicate();
}

void ReplServer::replicate() {

   // Track when we started the server
   _start_time = time(NULL);
   _last_repl = 0;

   // Set up our queue's listening socket
   _queue.bindSvr(_ip_addr.c_str(), _port);
   _queue.listenSvr();

   if (_verbosity >= 2)
      std::cout << "Server bound to " << _ip_addr << ", port: " << _port << " and listening\n";

   
  
   // Replicate until we get the shutdown signal
   while (!_shutdown) {

      // Check for new connections, process existing connections, and populate the queue as applicable
      _queue.handleQueue();     

      // See if it's time to replicate and, if so, go through the database, identifying new plots
      // that have not been replicated yet and adding them to the queue for replication
      if (getAdjustedTime() - _last_repl > secs_between_repl) {

         queueNewPlots();
         _last_repl = getAdjustedTime();
      }
      
      // Check the queue for updates and pop them until the queue is empty. The pop command only returns
      // incoming replication information--outgoing replication in the queue gets turned into a TCPConn
      // object and automatically removed from the queue by pop
      std::string sid;
      std::vector<uint8_t> data;
      while (_queue.pop(sid, data)) {

         // Incoming replication--add it to this server's local database
         addReplDronePlots(data);  
           
      } 
      //if we haven't found all the time offsets yet then keep checking
      if(!_foundAllTimeOffsets)
         checkDBForTimeOffset();
      //if a time offset has been found, start updating our local database
      if(_foundTimeOffset)
         correctTimeSkew();    

      usleep(1000);
   }
   //remove any duplicate points in our local database
   removeDuplicatePlots();
}

/**********************************************************************************************
 * queueNewPlots - looks at the database and grabs the new plots, marshalling them and
 *                 sending them to the queue manager
 *
 *    Returns: number of new plots sent to the QueueMgr
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

unsigned int ReplServer::queueNewPlots() {
   std::vector<uint8_t> marshall_data;
   unsigned int count = 0;

   if (_verbosity >= 3)
      std::cout << "Replicating plots.\n";

   // Loop through the drone plots, looking for new ones
   std::list<DronePlot>::iterator dpit = _plotdb.begin();

   for ( ; dpit != _plotdb.end(); dpit++) {

      // If this is a new one, marshall it and clear the flag
      if (dpit->isFlagSet(DBFLAG_NEW)) {
         //store this node id. used to determine authority
         _node_ids.insert(dpit->node_id);

         dpit->serialize(marshall_data);
         dpit->clrFlags(DBFLAG_NEW);

         count++;
      }
      if (marshall_data.size() % DronePlot::getDataSize() != 0)
         throw std::runtime_error("Issue with marshalling!");

   }
  
   if (count == 0) {
      if (_verbosity >= 3)
         std::cout << "No new plots found to replicate.\n";

      return 0;
   }
 
   // Add the count onto the front
   if (_verbosity >= 3)
      std::cout << "Adding in count: " << count << "\n";

   uint8_t *ctptr_begin = (uint8_t *) &count;
   marshall_data.insert(marshall_data.begin(), ctptr_begin, ctptr_begin+sizeof(unsigned int));

   // Send to the queue manager
   if (marshall_data.size() > 0) {
      _queue.sendToAll(marshall_data);
   }

   if (_verbosity >= 2) 
      std::cout << "Queued up " << count << " plots to be replicated.\n";

   return count;
}

/**********************************************************************************************
 * addReplDronePlots - Adds drone plots to the database from data that was replicated in. 
 *                     Deconflicts issues between plot points.
 * 
 * Params:  data - should start with the number of data points in a 32 bit unsigned integer, 
 *                 then a series of drone plot points
 *
 **********************************************************************************************/

void ReplServer::addReplDronePlots(std::vector<uint8_t> &data) {
   if (data.size() < 4) {
      throw std::runtime_error("Not enough data passed into addReplDronePlots");
   }

   if ((data.size() - 4) % DronePlot::getDataSize() != 0) {
      throw std::runtime_error("Data passed into addReplDronePlots was not the right multiple of DronePlot size");
   }

   // Get the number of plot points
   unsigned int *numptr = (unsigned int *) data.data();
   unsigned int count = *numptr;

   // Store sub-vectors for efficiency
   std::vector<uint8_t> plot;
   auto dptr = data.begin() + sizeof(unsigned int);

   for (unsigned int i=0; i<count; i++) {
      plot.clear();
      plot.assign(dptr, dptr + DronePlot::getDataSize());
      addSingleDronePlot(plot);   
      dptr += DronePlot::getDataSize();      
   }
   if (_verbosity >= 2)
      std::cout << "Replicated in " << count << " plots\n";   
}


/**********************************************************************************************
 * addSingleDronePlot - Takes in binary serialized drone data and adds it to the database. 
 *
 **********************************************************************************************/

void ReplServer::addSingleDronePlot(std::vector<uint8_t> &data) {
   DronePlot tmp_plot;

   tmp_plot.deserialize(data);

   //store this node id. used to determine authority
   _node_ids.insert(tmp_plot.node_id);

   _plotdb.addPlot(tmp_plot.drone_id, tmp_plot.node_id, tmp_plot.timestamp, tmp_plot.latitude,
                                                         tmp_plot.longitude);
}

/**********************************************************************************************
 * removeDuplicatePlots - Removes duplicate plot points in local database. 
 *
 **********************************************************************************************/

void ReplServer::removeDuplicatePlots() {
   _plotdb.sortByTime();

   std::list<DronePlot>::iterator diter;
   std::list<DronePlot>::iterator diter2;

   //compare each point to one another and if a duplicate (same lat, long, drone id, timestamp)
   //is found than delete it from the database
   for (diter = _plotdb.begin(); diter != _plotdb.end(); diter++) {

      diter2 = _plotdb.begin();
      while(diter2 != _plotdb.end()) {
         if(diter->latitude == diter2->latitude) {
            if(diter->longitude == diter2->longitude) {
               if(diter->drone_id == diter2->drone_id) {
                  if(diter->node_id != diter2->node_id) {
                     if(diter->timestamp == diter2->timestamp) {
                        diter2 = _plotdb.erase(diter2);
                        continue;
                     }
                  }
               }
            }
         }
         diter2++;
      }
   }
}

/**********************************************************************************************
 * correctTimeSkew - Iterates through the local database and updates a plot point if a timeskew
 *                   has been identified for that node.
 *
 **********************************************************************************************/

void ReplServer::correctTimeSkew() {
   std::list<DronePlot>::iterator diter;
   std::map<unsigned int, int>::iterator itr;

   //for each node that has been found to have a timeskew, iterate over the database and update
   //its timestamp. Once the update has been made, mark that plot as SYNCD to prevent it from
   //being updated again
   for(itr = _offsets.begin(); itr != _offsets.end(); itr++) {
      for (diter = _plotdb.begin(); diter != _plotdb.end(); diter++) {
         if((!diter->isFlagSet(DBFLAG_SYNCD)) && (diter->node_id == itr->first)) {
            diter->timestamp += itr->second;
            diter->setFlags(DBFLAG_SYNCD);
         }
      }
   }
}

/**********************************************************************************************
 * checkDBForTimeOffset - Iterates through the local database and detects if a plot has a time
 *                        that is different than the authority. If it does it stores the node id
 *                        and offset time in _offsets map.
 *
 **********************************************************************************************/

void ReplServer::checkDBForTimeOffset() {
   unsigned int num_servers = _queue.getNumServers();
   //this check means that note all the node ids for this simulation have been identified yet,
   //so to prevent conflicts with who the authority is, just return and try again later
   if((num_servers+1) != _node_ids.size())
      return;

   //the authority by which times will be compared
   unsigned int authority = getAuthority();

   _plotdb.sortByTime();

   std::list<DronePlot>::iterator diter;
   std::list<DronePlot>::iterator diter2;

   //iterate over the database looking for plots that have the same lat, long, drone id,
   //but different timestamps
   for (diter = _plotdb.begin(); diter != _plotdb.end(); diter++) {
      for(diter2 = _plotdb.begin(); diter2 != _plotdb.end(); diter2++) {
         if(diter->latitude == diter2->latitude) {
            if(diter->longitude == diter2->longitude) {
               if(diter->drone_id == diter2->drone_id) {
                  if(diter->timestamp != diter2->timestamp) {
                     //if the first iterator is the autority than I want to compare with this
                     //time
                     if(diter->node_id == authority) {
                        //this check helps with deconflicting plots that have come back over
                        //the same location but later in time. shouldn't be used to find the
                        //time offset
                        if(abs(diter->timestamp - diter2->timestamp) < 15) {
                           //make sure we haven't already added a time offset for this node
                           if(_offsets.find(diter2->node_id) == _offsets.end()) {
                              //store the node id and time offset
                              _offsets.insert(std::pair<unsigned int, int>(diter2->node_id, diter->timestamp - diter2->timestamp));
                              //at this point we have found a timeskew so we can start updating 
                              //the database with the new times. this is allowed by setting this flag
                              _foundTimeOffset = true;
                              //if all offsets have been found this we don't need to keep looking
                              //so turn this flag on
                              if(_offsets.size() == _queue.getNumServers()){
                                 _foundAllTimeOffsets = true;
                              }
                           }   
                        }
                     }
                  }
               }
            }
         }
      }
   }
}

/**********************************************************************************************
 * getAuthority - This function returns the authority to which plots need to compare their times
 *                against. The node ids of the servers involved in this simulation will have been
 *                added to the set _node_ids and this function returns the first one.
 *
 **********************************************************************************************/

unsigned int ReplServer::getAuthority() {
   std::set<unsigned int>::iterator itr = _node_ids.begin();
   return *itr;
}

void ReplServer::shutdown() {
   _shutdown = true;
}
