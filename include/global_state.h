#pragma once

#include "flow_tracker.h"
#include "app_tracker.h"
#include "top_talker.h"
#include "protocol_stats.h"
#include "threat_detector.h"
#include "transaction_manager.h"

extern FlowTracker* gFlowTracker;
extern AppTracker* gAppTracker;
extern TopTalker* gTopTalker;
extern ProtocolStats* gProtocolStats;
extern ThreatDetector* gThreatDetector;
extern TransactionManager*
gTransactionManager;