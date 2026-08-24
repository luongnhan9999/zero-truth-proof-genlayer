import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, 
  Terminal as TerminalIcon, 
  Layers, 
  AlertTriangle, 
  CheckCircle, 
  RefreshCw, 
  Play, 
  Lock, 
  Clock, 
  LogOut, 
  Check, 
  Plus, 
  FileCode, 
  Settings, 
  Activity,
  User,
  Zap
} from 'lucide-react';
import { createClient } from 'genlayer-js';
import { studionet } from 'genlayer-js/chains';

// TypeScript declarations
interface ZKAuditTask {
  id: string;
  project_owner: string;
  auditor: string;
  escrow_amount: string;
  auditor_stake: string;
  status: 'OPEN' | 'IN_PROGRESS' | 'AWAITING_PAYOUT' | 'NEEDS_REVISION' | 'DISPUTED' | 'ESCALATED' | 'CLOSED';
  circuit_url: string;
  proof_of_exploit_url: string;
  circuit_framework: string;
  constraint_focus: string;
  verdict: 'NONE' | 'APPROVED' | 'PARTIAL' | 'REFUND' | 'ESCALATE';
  reason: string;
  confidence: string;
  attempts: string;
  payout_ready_at: string;
  disputed_at: string;
}

// Default mock files for circuit viewer
const mockCircuitFiles: Record<string, { code: string; poc: string }> = {
  'zk_merkle_tree_circuit_01': {
    code: `// original_circuit.circom
pragma circom 2.1.6;

include "node_modules/circomlib/circuits/mimcsponge.circom";

template MerkleTreeVerifier(levels) {
    signal input leaf;
    signal input path_elements[levels];
    signal input path_index[levels];
    signal output root;

    component hashers[levels];
    signal intermediate[levels + 1];
    
    intermediate[0] <== leaf;

    for (var i = 0; i < levels; i++) {
        hashers[i] = MultiMiMC7(2, 91);
        
        // VULNERABILITY: Missing path index constraints!
        // The multiplexer should enforce path_index[i] is strictly binary.
        // Also, intermediate path signals are unconstrained, allowing root forging.
        
        hashers[i].in[0] <== path_elements[i];
        hashers[i].in[1] <== intermediate[i];
        
        intermediate[i + 1] <== hashers[i].out;
    }

    root <== intermediate[levels];
}`,
    poc: `// counterexample.circom & witness PoC
pragma circom 2.1.6;

// Auditor exploit witness script demonstrating unconstrained signals
// By providing path_index[i] values outside {0, 1} (e.g., 2 or -1), 
// we bypass standard path verification while satisfying the mathematical system.

// Witness input parameters:
{
  "leaf": "489237482394782394",
  "path_elements": ["0", "0", "0"],
  "path_index": ["2", "1", "3"], 
  "root": "129837192837192837" // Forged Merkle Root
}

// Expected evaluation result:
// Constraint System verification bypass (Soundness break) -> PASS`
  },
  'mimc_hash_collision_bounty': {
    code: `// mimc.nr (Noir)
fn main(x: Field, y: Field) -> pub Field {
    let mut round_key = 0;
    let mut res = x;

    // VULNERABILITY: Round constants indices are not constrained
    // in the evaluation logic, causing hashing collision.
    for i in 0..10 {
        res = (res + y + round_key) * (res + y + round_key) * (res + y + round_key);
    }
    res
}`,
    poc: `// PoC hash collision script
// Two distinct inputs x1, y1 and x2, y2 producing the same output res.
// Since the loop exponentiation does not enforce strict round constant addition order.

x1 = 0xfa3e...
y1 = 0x12b4...
x2 = 0x8b3c...
y2 = 0x7c9a...

hash(x1, y1) == hash(x2, y2)
// Status: Collision verified mathematically`
  },
  'groth16_malleability_exploit': {
    code: `// bridge.circom
pragma circom 2.0.0;

template BridgeVerifier() {
    signal input amount;
    signal input recipient;
    signal input nonce;
    signal input signature_r;
    signal input signature_s;

    // VULNERABILITY: Nonce signal is declared but never constrained
    // inside the quadratic constraints pool!
    // Allows signature malleability.
    
    signal amount_squared;
    amount_squared <== amount * amount;
}`,
    poc: `// witness malleability script
// Re-submitting the exact same bridge transaction amount & signature 
// but varying the 'nonce' value. Since nonce is unconstrained,
// the proof verifies successfully, leading to double-spend.

let original_proof = load_proof("tx_01.json");
let altered_proof = original_proof.clone();
altered_proof.public_inputs[2] = 9999; // Arbitrary new nonce

verify_proof(altered_proof) == true // Exploit active!`
  }
};

const DEFAULT_TASKS: ZKAuditTask[] = [
  {
    id: 'zk_merkle_tree_circuit_01',
    project_owner: '0xzk_rollup_owner_alpha',
    auditor: '0xzk_security_researcher_beta',
    escrow_amount: '3000000000000000000000', // 3000 GEN
    auditor_stake: '600000000000000000000',  // 600 GEN
    status: 'AWAITING_PAYOUT',
    circuit_url: 'https://github.com/zk-protocol/circuits/merkle.circom',
    proof_of_exploit_url: 'https://gist.github.com/zk-exploit/fake_witness.js',
    circuit_framework: 'Circom 2.1.6 / Groth16',
    constraint_focus: 'Under-constrained intermediate path signals allowing root forging',
    verdict: 'APPROVED',
    reason: 'Signal path_index[i] unconstrained allowing fake root proof generation. Verified by validator consensus.',
    confidence: '99',
    attempts: '1',
    payout_ready_at: String(Math.floor(Date.now() / 1000) + 43200), // 12 hours from now
    disputed_at: '0'
  },
  {
    id: 'mimc_hash_collision_bounty',
    project_owner: '0xlightspeed_bridge_dev',
    auditor: '0x0000000000000000000000000000000000000000',
    escrow_amount: '5000000000000000000000', // 5000 GEN
    auditor_stake: '0',
    status: 'OPEN',
    circuit_url: 'https://github.com/darkforest/circuits/mimc.nr',
    proof_of_exploit_url: '',
    circuit_framework: 'Noir / Plonkish',
    constraint_focus: 'Missing polynomial constraints in MiMC round constants loop',
    verdict: 'NONE',
    reason: 'Awaiting ZK Auditor acceptance and deposit.',
    confidence: '0',
    attempts: '0',
    payout_ready_at: '0',
    disputed_at: '0'
  },
  {
    id: 'groth16_malleability_exploit',
    project_owner: '0xzk_bridge_multichain',
    auditor: '0xzk_security_researcher_beta',
    escrow_amount: '4500000000000000000000', // 4500 GEN
    auditor_stake: '900000000000000000000',  // 900 GEN
    status: 'DISPUTED',
    circuit_url: 'https://github.com/zk-bridge/circuits/bridge.circom',
    proof_of_exploit_url: 'https://github.com/zk-exploit/bridge_malleability.js',
    circuit_framework: 'Circom 2.0 / Groth16',
    constraint_focus: 'Completeness violation via unconstrained input signal mapping',
    verdict: 'APPROVED',
    reason: '[DISPUTED by 0xzk_brid] PoC uses an out-of-scope compiler version which triggers custom compiler behavior',
    confidence: '92',
    attempts: '1',
    payout_ready_at: String(Math.floor(Date.now() / 1000) - 1000),
    disputed_at: String(Math.floor(Date.now() / 1000) - 3600)
  }
];

export default function App() {
  // Application Modes & Status
  const [isSimulated, setIsSimulated] = useState(true);
  const [walletConnected, setWalletConnected] = useState(false);
  const [walletAddress, setWalletAddress] = useState('0xProjectOwner_DevAddress');
  const [walletBalance, setWalletBalance] = useState('10000'); // GEN
  const [selectedRole, setSelectedRole] = useState<'OWNER' | 'AUDITOR' | 'ADMIN'>('OWNER');
  
  // Smart Contract Info
  const [contractAddress, setContractAddress] = useState('0x7F2B76Da941838d721F5a3B4553b6BC2D2425C19');
  const [tasks, setTasks] = useState<ZKAuditTask[]>(DEFAULT_TASKS);
  const [selectedTaskId, setSelectedTaskId] = useState<string>('zk_merkle_tree_circuit_01');
  
  // HUD Solver consensus steps animation
  const [hudState, setHudState] = useState<'IDLE' | 'INGESTING' | 'DEGREE_CHECK' | 'WITNESS_VALIDATION' | 'CONSENSUS'>('IDLE');
  
  // Logs for terminal
  const [terminalLogs, setTerminalLogs] = useState<string[]>([
    '[INIT] System started in Simulation Mode. Local mathematical solver initialized.',
    '[INFO] Initialized 3 ZK audit tasks in local cache.',
    '[STATION] Subscribed to consensus telemetry stream.'
  ]);
  
  // Creation Form State
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTaskId, setNewTaskId] = useState('');
  const [newCircuitUrl, setNewCircuitUrl] = useState('');
  const [newFramework, setNewFramework] = useState('Circom 2.1 / Groth16');
  const [newFocus, setNewFocus] = useState('');
  const [newEscrowAmount, setNewEscrowAmount] = useState('1000');
  
  // Accept / Submit Exploit forms
  const [exploitUrl, setExploitUrl] = useState('');
  const [disputeReason, setDisputeReason] = useState('');
  const [arbitrationAction, setArbitrationAction] = useState<'RELEASE' | 'REFUND' | 'SPLIT'>('RELEASE');
  
  // Timer state
  const [timeRemaining, setTimeRemaining] = useState<Record<string, number>>({});
  
  // genlayer-js Client reference
  const [genlayerClient, setGenlayerClient] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);

  // Auto-scroll terminal log
  const terminalEndRef = useRef<HTMLDivElement>(null);
  
  const addLog = (msg: string) => {
    const timestamp = new Date().toISOString().split('T')[1].substring(0, 8);
    setTerminalLogs(prev => [...prev, `[${timestamp}] ${msg}`]);
  };

  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [terminalLogs]);

  // Countdown timer scheduler
  useEffect(() => {
    const timer = setInterval(() => {
      const updatedTimers: Record<string, number> = {};
      let changed = false;
      
      tasks.forEach(task => {
        if (task.status === 'AWAITING_PAYOUT') {
          const readyTime = parseInt(task.payout_ready_at);
          const now = Math.floor(Date.now() / 1000);
          const diff = readyTime - now;
          updatedTimers[task.id] = diff > 0 ? diff : 0;
          changed = true;
        }
      });
      
      if (changed) {
        setTimeRemaining(updatedTimers);
      }
    }, 1000);
    
    return () => clearInterval(timer);
  }, [tasks]);

  // Handle Wallet Connect / Disconnect
  const connectWallet = async () => {
    if (isSimulated) {
      setWalletConnected(true);
      setWalletAddress(selectedRole === 'OWNER' ? '0xzk_rollup_owner_alpha' : selectedRole === 'AUDITOR' ? '0xzk_security_researcher_beta' : '0xadmin');
      setWalletBalance('8500');
      addLog(`[WALLET] Simulated wallet connected as ${selectedRole}. Balance: 8500 GEN`);
      return;
    }

    if (typeof window === 'undefined' || !(window as any).ethereum) {
      alert('MetaMask or another EIP-1193 wallet was not detected in your browser.');
      addLog('[WALLET ERROR] EIP-1193 provider missing from browser.');
      return;
    }

    try {
      setIsLoading(true);
      addLog('[WALLET] Requesting provider credentials...');
      const provider = (window as any).ethereum;
      const accounts = await provider.request({ method: 'eth_requestAccounts' });
      
      const client = createClient({
        chain: studionet,
        account: accounts[0] as `0x${string}`,
        provider: provider
      });
      
      setGenlayerClient(client);
      setWalletAddress(accounts[0]);
      setWalletConnected(true);
      
      // Attempt to load balance
      setWalletBalance('12500'); // Standard display for testnet
      addLog(`[WALLET] Wallet successfully connected to Studionet. Address: ${accounts[0]}`);
      
      // Load current tasks from contract
      await fetchTasksFromContract(client);
    } catch (err: any) {
      console.error(err);
      addLog(`[WALLET ERROR] Connection failed: ${err.message || err}`);
    } finally {
      setIsLoading(false);
    }
  };

  const disconnectWallet = () => {
    setWalletConnected(false);
    setGenlayerClient(null);
    addLog('[WALLET] Wallet disconnected.');
  };

  // Fetch tasks from deployed contract
  const fetchTasksFromContract = async (clientInstance: any) => {
    const client = clientInstance || genlayerClient;
    if (!client) return;

    try {
      setIsLoading(true);
      addLog('[CONTRACT] Fetching all tasks from get_all_tasks()...');
      
      const res = await client.readContract({
        address: contractAddress,
        functionName: 'get_all_tasks',
        args: []
      });
      
      const parsedTasks = JSON.parse(res);
      if (Array.isArray(parsedTasks)) {
        setTasks(parsedTasks);
        addLog(`[CONTRACT] Successfully retrieved ${parsedTasks.length} tasks from chain.`);
      }
    } catch (err: any) {
      console.error(err);
      addLog(`[CONTRACT ERROR] Read contract failed: ${err.message || err}`);
    } finally {
      setIsLoading(false);
    }
  };

  // Switch simulation/chain mode
  const handleModeToggle = (sim: boolean) => {
    setIsSimulated(sim);
    disconnectWallet();
    if (sim) {
      setTasks(DEFAULT_TASKS);
      addLog('[SYSTEM] Switched to local simulated consensus terminal.');
    } else {
      setTasks([]);
      addLog('[SYSTEM] Switched to live Studionet environment. Please connect wallet.');
    }
  };

  // Helper formatting bigints
  const formatGenAmount = (weiStr: string) => {
    try {
      if (!weiStr || weiStr === '0') return '0';
      // simple conversion division for display
      if (weiStr.length > 18) {
        return (parseFloat(weiStr) / 1e18).toFixed(1) + ' GEN';
      }
      return weiStr + ' wei';
    } catch {
      return weiStr;
    }
  };

  // Helper formatting duration
  const formatDuration = (seconds: number) => {
    if (!seconds || seconds <= 0) return '00:00:00';
    const hrs = Math.floor(seconds / 3600).toString().padStart(2, '0');
    const mins = Math.floor((seconds % 3600) / 60).toString().padStart(2, '0');
    const secs = (seconds % 60).toString().padStart(2, '0');
    return `${hrs}:${mins}:${secs}`;
  };

  // selected task
  const activeTask = tasks.find(t => t.id === selectedTaskId);

  // Action: Create Bounty
  const handleCreateBounty = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTaskId || !newCircuitUrl || !newFocus) {
      alert('Please fill out all fields.');
      return;
    }

    const valueWei = String(parseFloat(newEscrowAmount) * 1e18);

    if (isSimulated) {
      setIsLoading(true);
      addLog(`[TX] Broadcasting create_audit_bounty(${newTaskId}) with ${newEscrowAmount} GEN...`);
      
      setTimeout(() => {
        const newTask: ZKAuditTask = {
          id: newTaskId,
          project_owner: walletAddress,
          auditor: '0x0000000000000000000000000000000000000000',
          escrow_amount: valueWei,
          auditor_stake: '0',
          status: 'OPEN',
          circuit_url: newCircuitUrl,
          proof_of_exploit_url: '',
          circuit_framework: newFramework,
          constraint_focus: newFocus,
          verdict: 'NONE',
          reason: 'Awaiting ZK Auditor acceptance and deposit.',
          confidence: '0',
          attempts: '0',
          payout_ready_at: '0',
          disputed_at: '0'
        };
        
        setTasks(prev => [...prev, newTask]);
        setSelectedTaskId(newTaskId);
        setShowCreateModal(false);
        setIsLoading(false);
        addLog(`[TX SUCCESS] Block #389274 confirmed. Bounty ${newTaskId} created.`);
      }, 1500);
      return;
    }

    if (!genlayerClient) {
      alert('Wallet is not connected.');
      return;
    }

    try {
      setIsLoading(true);
      addLog(`[CHAIN TX] Invoking create_audit_bounty for task ${newTaskId}...`);
      
      const hash = await genlayerClient.writeContract({
        address: contractAddress,
        functionName: 'create_audit_bounty',
        args: [newTaskId, newCircuitUrl, newFramework, newFocus],
        value: BigInt(valueWei)
      });
      
      addLog(`[CHAIN TX] Transaction sent. Hash: ${hash}. Waiting for finalization...`);
      
      const receipt = await genlayerClient.waitForTransactionReceipt({
        hash,
        status: 'FINALIZED'
      });
      
      addLog(`[CHAIN CONFIRMED] Transaction finalized in block. Receipt status: ${receipt.status}`);
      setShowCreateModal(false);
      await fetchTasksFromContract(genlayerClient);
    } catch (err: any) {
      console.error(err);
      addLog(`[CHAIN TX ERROR] create_audit_bounty failed: ${err.message || err}`);
    } finally {
      setIsLoading(false);
    }
  };

  // Action: Accept Bounty (deposit 20% stake)
  const handleAcceptBounty = async () => {
    if (!activeTask) return;
    const requiredStake = String(BigInt(activeTask.escrow_amount) / BigInt(5)); // 20%

    if (isSimulated) {
      setIsLoading(true);
      addLog(`[TX] Broadcasting accept_audit_task(${activeTask.id}) staking 20% (${parseFloat(requiredStake)/1e18} GEN)...`);
      
      setTimeout(() => {
        setTasks(prev => prev.map(t => {
          if (t.id === activeTask.id) {
            return {
              ...t,
              auditor: walletAddress,
              auditor_stake: requiredStake,
              status: 'IN_PROGRESS',
              reason: 'Task locked by auditor. Submitting counterexample witness.'
            };
          }
          return t;
        }));
        setIsLoading(false);
        addLog(`[TX SUCCESS] Block #389275 confirmed. Locked task ${activeTask.id} for auditing.`);
      }, 1500);
      return;
    }

    if (!genlayerClient) {
      alert('Connect wallet first.');
      return;
    }

    try {
      setIsLoading(true);
      addLog(`[CHAIN TX] Invoking accept_audit_task for task ${activeTask.id}...`);
      
      const hash = await genlayerClient.writeContract({
        address: contractAddress,
        functionName: 'accept_audit_task',
        args: [activeTask.id],
        value: BigInt(requiredStake)
      });
      
      addLog(`[CHAIN TX] Sent. Hash: ${hash}. Finalizing...`);
      await genlayerClient.waitForTransactionReceipt({ hash, status: 'FINALIZED' });
      addLog(`[CHAIN CONFIRMED] Staked successfully. Task locked.`);
      await fetchTasksFromContract(genlayerClient);
    } catch (err: any) {
      console.error(err);
      addLog(`[CHAIN TX ERROR] accept_audit_task failed: ${err.message || err}`);
    } finally {
      setIsLoading(false);
    }
  };

  // Action: Submit Counterexample
  const handleSubmitCounterexample = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeTask || !exploitUrl) return;

    if (isSimulated) {
      setIsLoading(true);
      setHudState('INGESTING');
      addLog(`[TELEMETRY] Pipeline started for ${activeTask.id}. Ingesting circuit source code...`);
      
      // Simulate pipeline checks
      setTimeout(() => {
        setHudState('DEGREE_CHECK');
        addLog(`[TELEMETRY] Signal Constraint check running: checking degree coefficients...`);
        
        setTimeout(() => {
          setHudState('WITNESS_VALIDATION');
          addLog(`[TELEMETRY] Witness Inversion Validation: executing mathematical solver...`);
          
          setTimeout(() => {
            setHudState('CONSENSUS');
            addLog(`[TELEMETRY] GenLayer AI Consensus running. Querying judge LLMs...`);
            
            setTimeout(() => {
              // 80% chance of approved, 20% refund
              const passed = !exploitUrl.toLowerCase().includes('fail') && !exploitUrl.toLowerCase().includes('404');
              const verdict = passed ? 'APPROVED' : 'REFUND';
              const confidence = passed ? '96' : '100';
              const reason = passed 
                ? 'Conclusive under-constraint verified. Exploit witness bypasses quadratic constraint verification.'
                : 'Exploit submission URL resulted in 404 or mathematical validation failed.';
              
              setTasks(prev => prev.map(t => {
                if (t.id === activeTask.id) {
                  return {
                    ...t,
                    proof_of_exploit_url: exploitUrl,
                    attempts: String(parseInt(t.attempts) + 1),
                    status: verdict === 'APPROVED' ? 'AWAITING_PAYOUT' : (parseInt(t.attempts) >= 1 ? 'CLOSED' : 'NEEDS_REVISION'),
                    verdict,
                    reason,
                    confidence,
                    payout_ready_at: String(Math.floor(Date.now() / 1000) + 86400), // 24 hours cooldown
                  };
                }
                return t;
              }));
              
              setHudState('IDLE');
              setIsLoading(false);
              setExploitUrl('');
              addLog(`[TX SUCCESS] AI consensus settled verdict: ${verdict} (Confidence: ${confidence}%).`);
            }, 2000);
          }, 1500);
        }, 1500);
      }, 1500);
      return;
    }

    if (!genlayerClient) return;

    try {
      setIsLoading(true);
      addLog(`[CHAIN TX] Submitting counterexample witness to ${activeTask.id}...`);
      
      const hash = await genlayerClient.writeContract({
        address: contractAddress,
        functionName: 'submit_counterexample',
        args: [activeTask.id, exploitUrl]
      });
      
      addLog(`[CHAIN TX] Sent. Hash: ${hash}. AI consensus evaluating counterexample. Please wait...`);
      await genlayerClient.waitForTransactionReceipt({ hash, status: 'FINALIZED' });
      addLog(`[CHAIN CONFIRMED] Witness evaluated by consensus pipeline.`);
      setExploitUrl('');
      await fetchTasksFromContract(genlayerClient);
    } catch (err: any) {
      console.error(err);
      addLog(`[CHAIN TX ERROR] submit_counterexample failed: ${err.message || err}`);
    } finally {
      setIsLoading(false);
    }
  };

  // Action: Raise Dispute (within 24h window)
  const handleRaiseDispute = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeTask || !disputeReason) return;

    if (isSimulated) {
      setIsLoading(true);
      addLog(`[TX] Project owner raising dispute on task ${activeTask.id}: "${disputeReason}"`);
      
      setTimeout(() => {
        setTasks(prev => prev.map(t => {
          if (t.id === activeTask.id) {
            return {
              ...t,
              status: 'DISPUTED',
              disputed_at: String(Math.floor(Date.now() / 1000)),
              reason: `[DISPUTED by ${walletAddress.substring(0, 8)}] ${disputeReason}`
            };
          }
          return t;
        }));
        setIsLoading(false);
        setDisputeReason('');
        addLog(`[TX SUCCESS] Dispute locked. Task status transitioned to DISPUTED.`);
      }, 1200);
      return;
    }

    if (!genlayerClient) return;

    try {
      setIsLoading(true);
      addLog(`[CHAIN TX] Raising dispute on ${activeTask.id}...`);
      
      const hash = await genlayerClient.writeContract({
        address: contractAddress,
        functionName: 'raise_dispute',
        args: [activeTask.id, disputeReason]
      });
      
      await genlayerClient.waitForTransactionReceipt({ hash, status: 'FINALIZED' });
      addLog(`[CHAIN CONFIRMED] Dispute successfully registered.`);
      setDisputeReason('');
      await fetchTasksFromContract(genlayerClient);
    } catch (err: any) {
      console.error(err);
      addLog(`[CHAIN TX ERROR] raise_dispute failed: ${err.message || err}`);
    } finally {
      setIsLoading(false);
    }
  };

  // Action: Finalize Payout (after 24h window)
  const handleFinalizePayout = async () => {
    if (!activeTask) return;

    if (isSimulated) {
      setIsLoading(true);
      addLog(`[TX] finalising payout for task ${activeTask.id}...`);
      
      setTimeout(() => {
        setTasks(prev => prev.map(t => {
          if (t.id === activeTask.id) {
            return {
              ...t,
              status: 'CLOSED',
              escrow_amount: '0',
              auditor_stake: '0'
            };
          }
          return t;
        }));
        setIsLoading(false);
        addLog(`[TX SUCCESS] Escrow funds released. Task closed.`);
      }, 1500);
      return;
    }

    if (!genlayerClient) return;

    try {
      setIsLoading(true);
      addLog(`[CHAIN TX] Invoking finalize_payout for task ${activeTask.id}...`);
      
      const hash = await genlayerClient.writeContract({
        address: contractAddress,
        functionName: 'finalize_payout',
        args: [activeTask.id]
      });
      
      await genlayerClient.waitForTransactionReceipt({ hash, status: 'FINALIZED' });
      addLog(`[CHAIN CONFIRMED] Payout finalized and disbursed.`);
      await fetchTasksFromContract(genlayerClient);
    } catch (err: any) {
      console.error(err);
      addLog(`[CHAIN TX ERROR] finalize_payout failed: ${err.message || err}`);
    } finally {
      setIsLoading(false);
    }
  };

  // Action: Admin Resolve Escalation
  const handleResolveEscalation = async () => {
    if (!activeTask) return;

    if (isSimulated) {
      setIsLoading(true);
      addLog(`[TX] platform admin arbitrating dispute for task ${activeTask.id} with action: ${arbitrationAction}`);
      
      setTimeout(() => {
        setTasks(prev => prev.map(t => {
          if (t.id === activeTask.id) {
            return {
              ...t,
              status: 'CLOSED',
              escrow_amount: '0',
              auditor_stake: '0',
              reason: `[ARBITRATED BY ADMIN: ${arbitrationAction}] ${t.reason}`
            };
          }
          return t;
        }));
        setIsLoading(false);
        addLog(`[TX SUCCESS] Arbitration finalized. Action: ${arbitrationAction}`);
      }, 1200);
      return;
    }

    if (!genlayerClient) return;

    try {
      setIsLoading(true);
      addLog(`[CHAIN TX] Resolving escalation/dispute for ${activeTask.id} with action ${arbitrationAction}...`);
      
      const hash = await genlayerClient.writeContract({
        address: contractAddress,
        // Using resolve_escalation function from contract
        functionName: 'resolve_escalation',
        args: [activeTask.id, arbitrationAction]
      });
      
      await genlayerClient.waitForTransactionReceipt({ hash, status: 'FINALIZED' });
      addLog(`[CHAIN CONFIRMED] Arbitration completed on-chain.`);
      await fetchTasksFromContract(genlayerClient);
    } catch (err: any) {
      console.error(err);
      addLog(`[CHAIN TX ERROR] resolve_escalation failed: ${err.message || err}`);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen text-slate-100 flex flex-col relative font-terminal overflow-x-hidden selection:bg-purple-900 selection:text-white">
      {/* Background Grid Pattern Overlay */}
      <div className="absolute inset-0 pointer-events-none z-0 bg-[#08080C] opacity-95"></div>

      {/* Header */}
      <header className="border-b border-purple-950/60 bg-[#08080C]/90 backdrop-blur-md px-6 py-4 flex flex-col md:flex-row md:items-center md:justify-between gap-4 z-10 sticky top-0">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-purple-950/50 rounded border border-purple-800/40 relative">
            <Shield className="w-6 h-6 text-purple-400 glow-purple" />
            <div className="absolute top-0 right-0 w-2 h-2 rounded-full bg-emerald-400 animate-ping"></div>
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-wider text-purple-200 flex items-center gap-2">
              ZEROTRUTHPROOF <span className="text-xs px-2 py-0.5 bg-purple-900/60 border border-purple-700/50 rounded-full text-purple-300">V0.2.18</span>
            </h1>
            <p className="text-xs text-slate-400 tracking-tight">Autonomous ZK-SNARK Circuit Audit & Formal Verification Escrow</p>
          </div>
        </div>

        {/* Console Config & Wallet */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Mode Switcher */}
          <div className="flex items-center bg-slate-950/80 border border-purple-950 rounded p-1 text-xs">
            <button 
              onClick={() => handleModeToggle(true)}
              className={`px-3 py-1.5 rounded transition ${isSimulated ? 'bg-purple-900/70 text-purple-200 border border-purple-700/50' : 'text-slate-400 hover:text-slate-200'}`}
            >
              Simulation HUD
            </button>
            <button 
              onClick={() => handleModeToggle(false)}
              className={`px-3 py-1.5 rounded transition ${!isSimulated ? 'bg-purple-900/70 text-purple-200 border border-purple-700/50' : 'text-slate-400 hover:text-slate-200'}`}
            >
              Studionet Chain
            </button>
          </div>

          {/* Contract Address Config (Only on live network) */}
          {!isSimulated && (
            <div className="flex items-center bg-slate-950 border border-purple-950/40 rounded px-2.5 py-1.5">
              <Settings className="w-3.5 h-3.5 text-slate-500 mr-2" />
              <span className="text-slate-500 mr-1.5 text-[10px]">CONTRACT:</span>
              <input
                type="text"
                value={contractAddress}
                onChange={(e) => setContractAddress(e.target.value)}
                className="bg-transparent text-[11px] text-purple-300 font-mono focus:outline-none w-28 text-ellipsis border-b border-transparent focus:border-purple-600"
              />
            </div>
          )}

          {/* Connected wallet panel */}
          {walletConnected ? (
            <div className="flex items-center gap-2 bg-slate-950/90 border border-emerald-950 rounded px-3 py-1.5 text-xs">
              <div className="w-2 h-2 rounded-full bg-emerald-400 glow-mint animate-pulse"></div>
              <span className="text-slate-400 font-mono truncate max-w-[110px]">{walletAddress}</span>
              <span className="border-l border-slate-800 pl-2 text-emerald-400 font-bold">{walletBalance} GEN</span>
              <button 
                onClick={disconnectWallet}
                className="text-slate-400 hover:text-rose-400 transition pl-1"
                title="Disconnect Wallet"
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            </div>
          ) : (
            <button
              onClick={connectWallet}
              className="px-4 py-1.5 bg-gradient-to-r from-purple-800 to-purple-600 hover:from-purple-700 hover:to-purple-500 border border-purple-600 text-slate-100 rounded text-xs transition duration-200 flex items-center gap-2 glow-border-purple font-semibold cursor-pointer"
            >
              <Zap className="w-3.5 h-3.5 text-purple-200" /> Connect Wallet
            </button>
          )}
        </div>
      </header>

      {/* Main Grid HUD layout */}
      <main className="flex-1 grid grid-cols-1 xl:grid-cols-4 gap-6 p-6 z-10">
        
        {/* Left column: HUD Telemetry and Task List */}
        <div className="xl:col-span-1 flex flex-col gap-6">
          
          {/* Formal Solver Consensus Telemetry HUD */}
          <section className="bg-slate-950/90 border border-purple-950/70 rounded p-4 relative overflow-hidden flex flex-col">
            <div className="scanner-line absolute left-0 right-0 pointer-events-none opacity-20"></div>
            <div className="flex items-center justify-between mb-3 border-b border-purple-950 pb-2">
              <h2 className="text-xs font-bold text-slate-400 tracking-wider uppercase flex items-center gap-1.5">
                <Activity className="w-4 h-4 text-emerald-400 animate-pulse" /> AI Consensus Telemetry HUD
              </h2>
              <span className="text-[10px] text-emerald-400 flex items-center gap-1">
                <span className="w-1.5 h-1.5 bg-emerald-400 rounded-full animate-ping"></span> Live Solver
              </span>
            </div>

            {/* Steps HUD */}
            <div className="flex flex-col gap-2.5 text-[11px] font-mono">
              {[
                { name: 'Circuit AST Ingestion', state: 'INGESTING', desc: 'Checks endpoint availability and parses layout nodes.' },
                { name: 'Signal Constraint Degree Check', state: 'DEGREE_CHECK', desc: 'Validates degree-2 polynomial equation constraints.' },
                { name: 'Witness Inversion Validation', state: 'WITNESS_VALIDATION', desc: 'Tests witness counterexample against AST constraints.' },
                { name: 'Consensus Escrow Release', state: 'CONSENSUS', desc: 'Orchestrates LLM agreement on final mathematical audit verdict.' }
              ].map((step, idx) => {
                const isActive = hudState === step.state;
                const isPassed = 
                  hudState === 'IDLE' || 
                  (step.state === 'INGESTING' && hudState !== 'INGESTING') ||
                  (step.state === 'DEGREE_CHECK' && !['INGESTING', 'DEGREE_CHECK'].includes(hudState)) ||
                  (step.state === 'WITNESS_VALIDATION' && hudState === 'CONSENSUS');

                return (
                  <div 
                    key={idx} 
                    className={`p-2 border rounded transition duration-300 ${
                      isActive 
                        ? 'border-emerald-500 bg-emerald-950/20 text-emerald-300' 
                        : isPassed 
                          ? 'border-purple-950 bg-purple-950/10 text-purple-400' 
                          : 'border-slate-900 bg-slate-900/10 text-slate-600'
                    }`}
                  >
                    <div className="flex items-center justify-between font-bold mb-0.5">
                      <span>[{idx + 1}] {step.name}</span>
                      {isActive ? (
                        <span className="text-[10px] px-1.5 py-0.5 bg-emerald-800/40 text-emerald-300 border border-emerald-500/50 rounded animate-pulse">
                          EVALUATING
                        </span>
                      ) : isPassed ? (
                        <Check className="w-3.5 h-3.5 text-purple-400" />
                      ) : (
                        <Clock className="w-3.5 h-3.5 text-slate-800" />
                      )}
                    </div>
                    <p className={`text-[10px] leading-tight ${isActive ? 'text-slate-300' : 'text-slate-500'}`}>
                      {step.desc}
                    </p>
                  </div>
                );
              })}
            </div>
          </section>

          {/* Task List Panel */}
          <section className="flex-1 bg-slate-950/90 border border-purple-950/70 rounded p-4 flex flex-col">
            <div className="flex items-center justify-between mb-4 pb-2 border-b border-purple-950">
              <h2 className="text-xs font-bold text-slate-400 tracking-wider uppercase flex items-center gap-1.5">
                <Layers className="w-4 h-4 text-purple-400" /> Active Audit Escrows
              </h2>
              <button 
                onClick={() => {
                  if (!walletConnected) {
                    alert('Please connect your wallet first.');
                    return;
                  }
                  setShowCreateModal(true);
                }}
                className="p-1.5 bg-purple-900/60 hover:bg-purple-800/80 border border-purple-700/40 text-purple-200 rounded text-[10px] flex items-center gap-1 transition"
              >
                <Plus className="w-3.5 h-3.5" /> Publish Bounty
              </button>
            </div>

            {/* List */}
            <div className="flex-1 overflow-y-auto max-h-[350px] xl:max-h-none flex flex-col gap-2">
              {tasks.length === 0 ? (
                <div className="text-center py-8 text-xs text-slate-600 border border-dashed border-slate-900 rounded">
                  No bounty tasks found.<br />Deploy or create a new audit bounty.
                </div>
              ) : (
                tasks.map(task => {
                  const isSelected = task.id === selectedTaskId;
                  
                  // Status pill colors
                  const statusColors: Record<string, string> = {
                    'OPEN': 'text-sky-400 border-sky-950 bg-sky-950/30',
                    'IN_PROGRESS': 'text-amber-400 border-amber-950 bg-amber-950/30',
                    'AWAITING_PAYOUT': 'text-emerald-400 border-emerald-950 bg-emerald-950/30',
                    'NEEDS_REVISION': 'text-orange-400 border-orange-950 bg-orange-950/30',
                    'DISPUTED': 'text-rose-400 border-rose-950 bg-rose-950/30',
                    'ESCALATED': 'text-purple-400 border-purple-950 bg-purple-950/30',
                    'CLOSED': 'text-slate-500 border-slate-900 bg-slate-900/20'
                  };

                  return (
                    <button
                      key={task.id}
                      onClick={() => setSelectedTaskId(task.id)}
                      className={`w-full text-left p-3 rounded border transition cursor-pointer flex flex-col gap-2 ${
                        isSelected 
                          ? 'border-purple-500 bg-purple-950/20 glow-border-purple' 
                          : 'border-slate-900 bg-slate-900/30 hover:border-slate-800'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className={`font-mono text-xs ${isSelected ? 'text-purple-300 font-bold' : 'text-slate-300'}`}>
                          {task.id}
                        </span>
                        <span className={`text-[9px] px-2 py-0.5 border rounded-full font-semibold ${statusColors[task.status] || ''}`}>
                          {task.status}
                        </span>
                      </div>
                      
                      <div className="grid grid-cols-2 text-[10px] text-slate-500 font-mono gap-1">
                        <div>
                          <span className="text-slate-600 mr-1">FRAMEWORK:</span>
                          <span className="text-slate-400">{task.circuit_framework.split('/')[0]}</span>
                        </div>
                        <div className="text-right">
                          <span className="text-slate-600 mr-1">BOUNTY:</span>
                          <span className="text-purple-400 font-bold">{formatGenAmount(task.escrow_amount)}</span>
                        </div>
                      </div>
                    </button>
                  );
                })
              )}
            </div>
          </section>

        </div>

        {/* Right columns: Main Workspace Detail + Code Visualizer */}
        <div className="xl:col-span-3 flex flex-col gap-6">
          
          {activeTask ? (
            <>
              {/* Task Details Section */}
              <section className="bg-slate-950/90 border border-purple-950/70 rounded p-5 flex flex-col gap-4">
                <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-purple-950/60 pb-3 gap-3">
                  <div>
                    <h2 className="text-lg font-bold text-slate-200 tracking-wide font-mono flex items-center gap-2">
                      <TerminalIcon className="w-5 h-5 text-purple-400 glow-purple" /> {activeTask.id}
                    </h2>
                    <p className="text-xs text-slate-400 mt-1">
                      Target URL: <a href={activeTask.circuit_url} target="_blank" rel="noreferrer" className="text-purple-400 hover:underline">{activeTask.circuit_url}</a>
                    </p>
                  </div>
                  
                  {/* Status Box */}
                  <div className="flex items-center gap-3">
                    <div className="bg-slate-900 border border-purple-950 px-3 py-1.5 rounded text-xs flex flex-col items-center">
                      <span className="text-[9px] text-slate-500 font-bold tracking-wider">BOUNTY FUNDED</span>
                      <span className="text-purple-400 font-bold text-sm">{formatGenAmount(activeTask.escrow_amount)}</span>
                    </div>
                    {activeTask.auditor_stake !== '0' && (
                      <div className="bg-slate-900 border border-purple-950 px-3 py-1.5 rounded text-xs flex flex-col items-center">
                        <span className="text-[9px] text-slate-500 font-bold tracking-wider">AUDITOR STAKE</span>
                        <span className="text-amber-400 font-bold text-sm">{formatGenAmount(activeTask.auditor_stake)}</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Audit specifications */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                  <div className="p-3 bg-slate-900/60 border border-slate-900 rounded">
                    <span className="text-[10px] text-slate-500 block mb-1 font-bold">CIRCUIT FRAMEWORK / COMPILER</span>
                    <span className="text-slate-300 font-mono">{activeTask.circuit_framework}</span>
                  </div>
                  <div className="p-3 bg-slate-900/60 border border-slate-900 rounded md:col-span-2">
                    <span className="text-[10px] text-slate-500 block mb-1 font-bold">CONSTRAINT CRITERIA FOCUS</span>
                    <span className="text-amber-300 font-mono">{activeTask.constraint_focus}</span>
                  </div>
                </div>

                {/* Consensus Pipeline Verdict Section */}
                {activeTask.verdict !== 'NONE' && (
                  <div className={`p-4 border rounded text-xs ${
                    activeTask.verdict === 'APPROVED' 
                      ? 'border-emerald-950 bg-emerald-950/10' 
                      : activeTask.verdict === 'PARTIAL'
                        ? 'border-amber-950 bg-amber-950/10'
                        : activeTask.verdict === 'REFUND'
                          ? 'border-rose-950 bg-rose-950/10'
                          : 'border-purple-950 bg-purple-950/10'
                  }`}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-bold tracking-wider uppercase flex items-center gap-1.5">
                        <CheckCircle className={`w-4.5 h-4.5 ${activeTask.verdict === 'APPROVED' ? 'text-emerald-400' : 'text-amber-400'}`} /> Consensus Evaluation Output
                      </span>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-slate-500 font-bold">AI CONFIDENCE:</span>
                        <span className="px-2 py-0.5 bg-slate-900 border border-slate-800 text-purple-400 font-bold rounded">
                          {activeTask.confidence}%
                        </span>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mt-3">
                      <div>
                        <span className="text-[9px] text-slate-500 block font-bold">CONSENSUS VERDICT</span>
                        <span className={`text-sm font-bold uppercase tracking-widest ${
                          activeTask.verdict === 'APPROVED' ? 'text-emerald-400' : 'text-rose-400'
                        }`}>
                          {activeTask.verdict}
                        </span>
                      </div>
                      <div className="md:col-span-3">
                        <span className="text-[9px] text-slate-500 block font-bold">EVALUATION JUSTIFICATION</span>
                        <p className="text-slate-300 leading-relaxed font-mono italic mt-0.5">
                          "{activeTask.reason}"
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {/* 24h Countdown & Dispute Banner */}
                {activeTask.status === 'AWAITING_PAYOUT' && (
                  <div className="p-4 bg-amber-950/15 border border-amber-900/60 rounded flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div className="flex items-start gap-3">
                      <Clock className="w-5 h-5 text-amber-400 mt-0.5 animate-pulse" />
                      <div>
                        <span className="text-xs font-bold text-amber-300 block tracking-wider uppercase">
                          24h Cryptographic Challenge Window Active
                        </span>
                        <p className="text-[11px] text-slate-400 mt-1 leading-normal max-w-xl">
                          Consensus has approved this proof. Escrow release is locked in cooling-off. The project owner or auditor can raise a dispute if incorrect.
                        </p>
                      </div>
                    </div>
                    
                    <div className="flex items-center gap-4">
                      <div className="text-center md:text-right bg-slate-950 border border-amber-950 px-3.5 py-1.5 rounded">
                        <span className="text-[9px] text-slate-500 block font-bold">FINALISATION TIMEOUT</span>
                        <span className="text-amber-400 font-mono font-bold text-sm tracking-widest">
                          {formatDuration(timeRemaining[activeTask.id] || 0)}
                        </span>
                      </div>
                    </div>
                  </div>
                )}
              </section>

              {/* R1CS / PlonKish Constraint Visualizer (Dual-Pane) */}
              <section className="bg-slate-950/90 border border-purple-950/70 rounded p-5 flex flex-col">
                <div className="flex items-center justify-between mb-4 border-b border-purple-950/60 pb-3">
                  <div>
                    <h3 className="text-xs font-bold text-slate-400 tracking-wider uppercase flex items-center gap-1.5">
                      <FileCode className="w-4 h-4 text-purple-400" /> Interactive R1CS / PlonKish Constraint Visualizer
                    </h3>
                    <p className="text-[10px] text-slate-500 mt-0.5">Comparing target circuit signals against auditor exploit counterexample</p>
                  </div>
                  
                  <span className="text-[10px] text-purple-400 px-2.5 py-1 bg-purple-950/30 border border-purple-900/40 rounded font-mono">
                    {activeTask.circuit_framework} Sandbox
                  </span>
                </div>

                {/* Dual-Pane Editor mockups */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  
                  {/* Left Pane: Original Circuit */}
                  <div className="border border-purple-950/50 bg-slate-950 rounded overflow-hidden flex flex-col h-[280px]">
                    <div className="bg-purple-950/20 px-3 py-1.5 border-b border-purple-950/60 flex items-center justify-between text-[11px] font-bold text-purple-300">
                      <span>Original Circuit Code</span>
                      <span className="text-[9px] text-slate-500 font-mono font-normal">READ-ONLY</span>
                    </div>
                    <textarea
                      readOnly
                      value={mockCircuitFiles[activeTask.id]?.code || `// Circuit source code not loaded.\n// URL: ${activeTask.circuit_url}`}
                      className="flex-1 p-3 text-[11px] font-mono bg-slate-950 text-slate-400 focus:outline-none resize-none overflow-y-auto leading-relaxed border-none"
                    />
                  </div>

                  {/* Right Pane: PoC Exploit Witness */}
                  <div className="border border-purple-950/50 bg-slate-950 rounded overflow-hidden flex flex-col h-[280px]">
                    <div className="bg-purple-950/20 px-3 py-1.5 border-b border-purple-950/60 flex items-center justify-between text-[11px] font-bold text-amber-300">
                      <span>PoC Exploit / Witness Input</span>
                      <span className="text-[9px] text-slate-500 font-mono font-normal">AUDITOR witness.json</span>
                    </div>
                    <textarea
                      readOnly
                      value={
                        activeTask.status === 'OPEN' 
                          ? `// No exploit witness submitted yet.\n// Lock this task and upload PoC witness file script.`
                          : mockCircuitFiles[activeTask.id]?.poc || `// Witness script URL: ${activeTask.proof_of_exploit_url}`
                      }
                      className="flex-1 p-3 text-[11px] font-mono bg-slate-950 text-amber-200/90 focus:outline-none resize-none overflow-y-auto leading-relaxed border-none"
                    />
                  </div>

                </div>
              </section>

              {/* Action Console depending on Role */}
              <section className="bg-slate-950/90 border border-purple-950/70 rounded p-5 flex flex-col gap-4">
                {/* Role Toggle Selector */}
                <div className="flex items-center justify-between border-b border-purple-950/60 pb-3">
                  <div className="flex items-center gap-1.5">
                    <User className="w-4 h-4 text-purple-400" />
                    <span className="text-xs font-bold text-slate-400 tracking-wider uppercase">Execution Console:</span>
                  </div>

                  <div className="flex gap-2">
                    {[
                      { role: 'OWNER', label: 'Project Owner' },
                      { role: 'AUDITOR', label: 'ZK Auditor' },
                      { role: 'ADMIN', label: 'Consensus Admin' }
                    ].map(r => (
                      <button
                        key={r.role}
                        onClick={() => setSelectedRole(r.role as any)}
                        className={`text-[10px] px-3 py-1 border rounded transition ${
                          selectedRole === r.role 
                            ? 'bg-purple-900/60 border-purple-600 text-purple-200 font-bold' 
                            : 'border-slate-900 hover:border-slate-800 text-slate-400'
                        }`}
                      >
                        {r.label}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Role panels content */}
                <div className="text-xs min-h-[80px]">
                  
                  {/* OWNER PANEL */}
                  {selectedRole === 'OWNER' && (
                    <div className="flex flex-col gap-4">
                      {activeTask.status === 'OPEN' && (
                        <p className="text-slate-400 italic">
                          Awaiting an independent ZK Auditor to stake 20% security deposit ({(parseFloat(activeTask.escrow_amount) / 1e18) * 0.2} GEN) and lock this contract for validation.
                        </p>
                      )}

                      {activeTask.status === 'IN_PROGRESS' && (
                        <p className="text-slate-400">
                          Auditor <span className="font-mono text-purple-400">{activeTask.auditor}</span> is currently analyzing target constraints. Bounty reward is locked in escrow.
                        </p>
                      )}

                      {activeTask.status === 'AWAITING_PAYOUT' && (
                        <div className="flex flex-col gap-4">
                          <p className="text-slate-300">
                            The solver verification passed. If you believe the auditor's PoC is invalid (e.g. out of scope or uses custom compiler behavior), you can challenge it within the 24h cooldown.
                          </p>
                          <form onSubmit={handleRaiseDispute} className="flex flex-wrap gap-3 items-end">
                            <div className="flex-1 min-w-[280px]">
                              <label className="text-[10px] text-slate-500 block font-bold mb-1">DISPUTE CHALLENGE JUSTIFICATION</label>
                              <input
                                type="text"
                                required
                                value={disputeReason}
                                onChange={(e) => setDisputeReason(e.target.value)}
                                placeholder="State reason, e.g., witness uses invalid parameters..."
                                className="w-full bg-slate-950 border border-purple-950/80 rounded p-2 text-xs font-mono focus:outline-none focus:border-purple-600"
                              />
                            </div>
                            <button
                              type="submit"
                              disabled={isLoading}
                              className="px-4 py-2 bg-rose-950 hover:bg-rose-900 border border-rose-800 hover:border-rose-600 text-rose-200 rounded font-bold transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                            >
                              <AlertTriangle className="w-4 h-4 text-rose-400" /> Raise Cryptographic Dispute
                            </button>
                            
                            {/* Finalize button - only available if time expired */}
                            <button
                              type="button"
                              onClick={handleFinalizePayout}
                              disabled={isLoading || (timeRemaining[activeTask.id] !== 0)}
                              className="px-4 py-2 bg-emerald-950 hover:bg-emerald-900 border border-emerald-800 hover:border-emerald-600 text-emerald-200 rounded font-bold transition flex items-center gap-1.5 cursor-pointer disabled:opacity-40"
                              title={timeRemaining[activeTask.id] !== 0 ? "Cooling off period must elapse first" : ""}
                            >
                              <CheckCircle className="w-4 h-4" /> Finalize Payout (Release)
                            </button>
                          </form>
                        </div>
                      )}

                      {activeTask.status === 'DISPUTED' && (
                        <div className="p-3 border border-rose-950/40 bg-rose-950/10 rounded flex flex-col gap-2">
                          <span className="font-bold text-rose-400 flex items-center gap-1">
                            <AlertTriangle className="w-4 h-4" /> Active Dispute Registered
                          </span>
                          <p className="text-slate-400">
                            Dispute details: <span className="font-mono text-slate-300">{activeTask.reason}</span>
                          </p>
                          <p className="text-[11px] text-slate-500 italic mt-1">
                            Consensus Administrator must arbitrate this escrow split.
                          </p>
                        </div>
                      )}

                      {activeTask.status === 'CLOSED' && (
                        <p className="text-slate-500 italic">
                          Bounty completed. Escrow has been successfully settled and all funds disbursed.
                        </p>
                      )}
                    </div>
                  )}

                  {/* AUDITOR PANEL */}
                  {selectedRole === 'AUDITOR' && (
                    <div className="flex flex-col gap-4">
                      {activeTask.status === 'OPEN' && (
                        <div className="flex flex-col gap-3">
                          <p className="text-slate-300">
                            Lock this bounty to submit a witness file counterexample. Staking 20% security deposit ({(parseFloat(activeTask.escrow_amount) / 1e18) * 0.2} GEN) is required to prevent denial of service.
                          </p>
                          <div>
                            <button
                              onClick={handleAcceptBounty}
                              disabled={isLoading || !walletConnected}
                              className="px-4 py-2 bg-gradient-to-r from-purple-800 to-purple-600 hover:from-purple-700 hover:to-purple-500 border border-purple-600 text-slate-100 rounded font-bold transition flex items-center gap-1.5 cursor-pointer disabled:opacity-40"
                            >
                              <Lock className="w-4 h-4 text-purple-200" /> Stake & Accept Audit Task
                            </button>
                            {!walletConnected && (
                              <span className="text-[10px] text-rose-400 mt-1 block">Connect your wallet first to execute staking transaction.</span>
                            )}
                          </div>
                        </div>
                      )}

                      {(activeTask.status === 'IN_PROGRESS' || activeTask.status === 'NEEDS_REVISION') && (
                        <div className="flex flex-col gap-4">
                          <div className="flex items-center justify-between">
                            <p className="text-slate-300">
                              Submit proof of mathematical exploit. Provide a URL pointing to the proof witness script or counterexample representation.
                            </p>
                            <span className="text-[10px] text-amber-400 bg-amber-950/20 px-2 py-0.5 border border-amber-900/40 rounded">
                              ATTEMPT: {activeTask.attempts} / 2 MAX
                            </span>
                          </div>
                          
                          <form onSubmit={handleSubmitCounterexample} className="flex flex-wrap gap-3 items-end">
                            <div className="flex-1 min-w-[280px]">
                              <label className="text-[10px] text-slate-500 block font-bold mb-1">POC / WITNESS EXPLOIT URL</label>
                              <input
                                type="url"
                                required
                                value={exploitUrl}
                                onChange={(e) => setExploitUrl(e.target.value)}
                                placeholder="https://gist.github.com/.../counterexample.circom"
                                className="w-full bg-slate-950 border border-purple-950/80 rounded p-2 text-xs font-mono focus:outline-none focus:border-purple-600"
                              />
                            </div>
                            <button
                              type="submit"
                              disabled={isLoading}
                              className="px-5 py-2 bg-emerald-950 hover:bg-emerald-900 border border-emerald-800 hover:border-emerald-600 text-emerald-200 rounded font-bold transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                            >
                              {isLoading ? (
                                <>
                                  <RefreshCw className="w-4 h-4 animate-spin text-emerald-400" /> Processing...
                                </>
                              ) : (
                                <>
                                  <Play className="w-4 h-4 text-emerald-400" /> Submit mathematical counterexample
                                </>
                              )}
                            </button>
                          </form>
                        </div>
                      )}

                      {activeTask.status === 'AWAITING_PAYOUT' && (
                        <p className="text-emerald-400 font-bold flex items-center gap-1.5">
                          <CheckCircle className="w-4 h-4 text-emerald-400" /> Your exploit counterexample was approved. Payout finalize window ends in {formatDuration(timeRemaining[activeTask.id] || 0)}.
                        </p>
                      )}

                      {activeTask.status === 'DISPUTED' && (
                        <p className="text-rose-400 font-bold flex items-center gap-1.5">
                          <AlertTriangle className="w-4 h-4 text-rose-400" /> Project owner raised a dispute challenge. Escalation under platform admin review.
                        </p>
                      )}

                      {activeTask.status === 'CLOSED' && (
                        <p className="text-slate-500 italic">
                          Bounty completed. Escrow has been successfully settled and all funds disbursed.
                        </p>
                      )}
                    </div>
                  )}

                  {/* ADMIN PANEL */}
                  {selectedRole === 'ADMIN' && (
                    <div className="flex flex-col gap-4">
                      {['DISPUTED', 'ESCALATED'].includes(activeTask.status) ? (
                        <div className="p-4 border border-purple-950/50 bg-slate-900/60 rounded flex flex-col gap-4">
                          <div>
                            <span className="text-[10px] text-purple-300 font-bold block mb-1 uppercase">Platform Administration Arbitration Portal</span>
                            <p className="text-slate-400">
                              Decide the split allocation payout action for task <span className="font-mono text-purple-400">{activeTask.id}</span>.
                            </p>
                          </div>
                          
                          <div className="flex flex-wrap gap-4 items-center">
                            <div className="flex gap-2">
                              {[
                                { action: 'RELEASE', label: '100% Release (Auditor Payout)' },
                                { action: 'REFUND', label: '100% Refund (Owner Payout)' },
                                { action: 'SPLIT', label: '50/50 Split (Disburse Half)' }
                              ].map(act => (
                                <button
                                  key={act.action}
                                  type="button"
                                  onClick={() => setArbitrationAction(act.action as any)}
                                  className={`text-[10px] px-3 py-1.5 border rounded transition ${
                                    arbitrationAction === act.action 
                                      ? 'bg-purple-900/60 border-purple-600 text-purple-200' 
                                      : 'border-slate-800 hover:border-slate-700 text-slate-500'
                                  }`}
                                >
                                  {act.label}
                                </button>
                              ))}
                            </div>
                            
                            <button
                              type="button"
                              onClick={handleResolveEscalation}
                              disabled={isLoading}
                              className="px-4 py-1.5 bg-emerald-950 hover:bg-emerald-900 border border-emerald-800 text-emerald-300 rounded font-bold transition flex items-center gap-1 cursor-pointer"
                            >
                              Finalize Arbitration
                            </button>
                          </div>
                        </div>
                      ) : (
                        <p className="text-slate-500 italic">
                          This task is not in an ESCALATED or DISPUTED status. Admin arbitration is offline.
                        </p>
                      )}
                    </div>
                  )}

                </div>
              </section>
            </>
          ) : (
            <div className="bg-slate-950/90 border border-purple-950/70 rounded p-12 text-center text-slate-500 text-sm">
              Please select or create an audit task from the dashboard sidebar.
            </div>
          )}

          {/* Terminal Console Logs */}
          <section className="bg-slate-950/90 border border-purple-950/70 rounded p-4 flex flex-col font-mono h-[160px] relative">
            <div className="flex items-center justify-between border-b border-purple-950/60 pb-2 mb-2">
              <span className="text-[10px] font-bold text-slate-500 tracking-widest uppercase flex items-center gap-1">
                <TerminalIcon className="w-3.5 h-3.5 text-purple-400" /> GenLayer Node Local Console Logs
              </span>
              <button 
                onClick={() => setTerminalLogs([])}
                className="text-[9px] text-slate-600 hover:text-slate-400 transition"
              >
                Clear Console
              </button>
            </div>
            
            <div className="flex-1 overflow-y-auto text-[10px] text-slate-400 flex flex-col gap-1 pr-2 leading-relaxed">
              {terminalLogs.map((log, index) => (
                <div key={index} className="break-all">
                  <span className="text-purple-600 mr-1.5">&gt;</span>
                  {log}
                </div>
              ))}
              <div ref={terminalEndRef}></div>
            </div>
          </section>

        </div>
      </main>

      {/* FOOTER */}
      <footer className="border-t border-purple-950/60 bg-[#08080C] px-6 py-4 flex flex-col sm:flex-row justify-between items-center text-[10px] text-slate-600 z-10 gap-2 font-mono">
        <div>
          © 2026 ZEROTRUTHPROOF // Autonomous Formal Verification Escrow
        </div>
        <div className="flex gap-4">
          <a href="https://docs.genlayer.com" target="_blank" rel="noreferrer" className="hover:text-purple-400 transition">GenLayer Core Docs</a>
          <span>•</span>
          <span className="text-purple-900">Studionet Sandbox Active</span>
        </div>
      </footer>

      {/* CREATE BOUNTY MODAL */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#08080C] border border-purple-950 rounded-lg max-w-md w-full p-6 relative shadow-2xl">
            <div className="flex items-center justify-between border-b border-purple-950 pb-3 mb-4">
              <h3 className="font-mono text-sm font-bold text-purple-300 uppercase tracking-widest">
                Create Audit Bounty Escrow
              </h3>
              <button 
                onClick={() => setShowCreateModal(false)}
                className="text-slate-500 hover:text-slate-300 font-bold"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateBounty} className="flex flex-col gap-4 text-xs font-mono">
              <div>
                <label className="text-[10px] text-slate-500 block mb-1 font-bold">TASK ID (UNIQUE KEY)</label>
                <input
                  type="text"
                  required
                  placeholder="e.g., zk_merkle_tree_circuit_02"
                  value={newTaskId}
                  onChange={(e) => setNewTaskId(e.target.value)}
                  className="w-full bg-slate-950 border border-purple-950 rounded p-2 text-slate-300 focus:outline-none focus:border-purple-600"
                />
              </div>

              <div>
                <label className="text-[10px] text-slate-500 block mb-1 font-bold">CIRCUIT SOURCE GITHUB/HTTP URL</label>
                <input
                  type="url"
                  required
                  placeholder="https://github.com/my-project/circuits/root.circom"
                  value={newCircuitUrl}
                  onChange={(e) => setNewCircuitUrl(e.target.value)}
                  className="w-full bg-slate-950 border border-purple-950 rounded p-2 text-slate-300 focus:outline-none focus:border-purple-600"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] text-slate-500 block mb-1 font-bold">FRAMEWORK</label>
                  <select
                    value={newFramework}
                    onChange={(e) => setNewFramework(e.target.value)}
                    className="w-full bg-slate-950 border border-purple-950 rounded p-2 text-slate-300 focus:outline-none focus:border-purple-600"
                  >
                    <option>Circom 2.1 / Groth16</option>
                    <option>Halo2 / Plonk</option>
                    <option>Noir / Plonkish</option>
                    <option>Plonky2</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] text-slate-500 block mb-1 font-bold">ESCROW DEPOSIT (GEN)</label>
                  <input
                    type="number"
                    min="1"
                    required
                    value={newEscrowAmount}
                    onChange={(e) => setNewEscrowAmount(e.target.value)}
                    className="w-full bg-slate-950 border border-purple-950 rounded p-2 text-slate-300 focus:outline-none focus:border-purple-600"
                  />
                </div>
              </div>

              <div>
                <label className="text-[10px] text-slate-500 block mb-1 font-bold">CRITICAL CONSTRAINT FOCUS AREA</label>
                <input
                  type="text"
                  required
                  placeholder="e.g., Under-constrained intermediate signals allowing root forging"
                  value={newFocus}
                  onChange={(e) => setNewFocus(e.target.value)}
                  className="w-full bg-slate-950 border border-purple-950 rounded p-2 text-slate-300 focus:outline-none focus:border-purple-600"
                />
              </div>

              <div className="flex gap-3 justify-end mt-4 pt-3 border-t border-purple-950/60">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 border border-slate-900 hover:border-slate-800 rounded font-semibold text-slate-400 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isLoading}
                  className="px-5 py-2 bg-gradient-to-r from-purple-800 to-purple-600 hover:from-purple-700 hover:to-purple-500 border border-purple-600 text-slate-100 rounded font-bold transition flex items-center gap-1 cursor-pointer"
                >
                  Fund Escrow & Publish
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
