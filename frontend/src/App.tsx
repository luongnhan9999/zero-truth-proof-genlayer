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
  circuit_hash: string;
  proof_of_exploit_url: string;
  exploit_hash: string;
  circuit_framework: string;
  constraint_focus: string;
  verdict: 'NONE' | 'APPROVED' | 'PARTIAL' | 'REFUND' | 'ESCALATE';
  reason: string;
  confidence: string;
  attempts: string;
  payout_ready_at: string;
  disputed_at: string;
}

export default function App() {
  // Connection states
  const [walletConnected, setWalletConnected] = useState(false);
  const [walletAddress, setWalletAddress] = useState('');
  const [walletBalance, setWalletBalance] = useState('0');
  const [selectedRole, setSelectedRole] = useState<'OWNER' | 'AUDITOR' | 'ADMIN'>('OWNER');
  
  // Smart Contract Info (Default test address, can be configured in UI)
  const [contractAddress, setContractAddress] = useState('0x8Eae7Ec0E04b41d407b605A724C55EF91E8d80C2');
  const [tasks, setTasks] = useState<ZKAuditTask[]>([]);
  const [selectedTaskId, setSelectedTaskId] = useState<string>('');
  
  // Visualizer code viewer states
  const [circuitCode, setCircuitCode] = useState('// Select a task to load circuit code');
  const [exploitCode, setExploitCode] = useState('// Select a task to load exploit witness');
  
  // Logs for terminal
  const [terminalLogs, setTerminalLogs] = useState<string[]>([
    '[INIT] System started. Real Web3 client initialized for Studionet.',
    '[STATION] Subscribed to GenLayer contract RPC event listener.'
  ]);
  
  // Creation Form State
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newProjectName, setNewProjectName] = useState('');
  const [newTaskId, setNewTaskId] = useState('');
  const [newCircuitUrl, setNewCircuitUrl] = useState('');
  const [newCircuitHash, setNewCircuitHash] = useState('');
  const [newFramework, setNewFramework] = useState('Circom 2.1');
  const [newCompilerVersion, setNewCompilerVersion] = useState('v2.1.6');
  const [newProvingSystem, setNewProvingSystem] = useState('Groth16');
  const [newComplexity, setNewComplexity] = useState('15k constraints');
  const [newFocus, setNewFocus] = useState('');
  const [newEscrowAmount, setNewEscrowAmount] = useState('10'); // In GEN

  // Auto-generate task ID from Project Name
  useEffect(() => {
    if (newProjectName) {
      const generatedId = newProjectName
        .toLowerCase()
        .replace(/[^a-z0-9]/g, '_')
        .replace(/_+/g, '_')
        .substring(0, 30) + '_' + Math.floor(100 + Math.random() * 900);
      setNewTaskId(generatedId);
    }
  }, [newProjectName]);
  
  // Auditor Submit exploit Form State
  const [exploitUrl, setExploitUrl] = useState('');
  const [exploitHash, setExploitHash] = useState('');
  
  // Dispute & Payout States
  const [disputeReason, setDisputeReason] = useState('');
  const [arbitrationAction, setArbitrationAction] = useState<'RELEASE' | 'REFUND' | 'SPLIT'>('RELEASE');
  
  // Timer state
  const [timeRemaining, setTimeRemaining] = useState<Record<string, number>>({});
  
  // genlayer-js Client references
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

  // Load contract tasks on initial mount and when contract address updates
  useEffect(() => {
    fetchTasksFromContract();
  }, [contractAddress]);

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

  // Auto-connect wallet if already authorized in MetaMask and user did not disconnect manually
  useEffect(() => {
    const autoConnect = async () => {
      if (localStorage.getItem('wallet_previously_connected') === 'true' && typeof window !== 'undefined' && (window as any).ethereum) {
        const provider = (window as any).ethereum;
        try {
          const accounts = await provider.request({ method: 'eth_accounts' });
          if (accounts && accounts.length > 0) {
            await connectWallet();
          }
        } catch (e) {
          console.error('Auto-connect failed:', e);
        }
      }
    };
    autoConnect();
  }, []);

  // Listen to MetaMask account and chain changes automatically
  useEffect(() => {
    if (typeof window !== 'undefined' && (window as any).ethereum) {
      const provider = (window as any).ethereum;
      
      const handleAccounts = async (accounts: string[]) => {
        if (accounts.length > 0) {
          const cleanAddr = accounts[0].toLowerCase();
          addLog(`[WALLET] Account changed to: ${cleanAddr}`);
          setWalletAddress(cleanAddr);
          setWalletConnected(true);
          
          // Re-instantiate write client
          const client = createClient({
            chain: studionet,
            account: cleanAddr as `0x${string}`,
            provider: provider,
            endpoint: 'https://studio.genlayer.com/api'
          });
          setGenlayerClient(client);
          await fetchTasksFromContract();
        } else {
          // Disconnected
          disconnectWallet();
        }
      };

      const handleChain = () => {
        addLog('[WALLET] Network chain changed. Reloading state...');
        window.location.reload();
      };

      provider.on('accountsChanged', handleAccounts);
      provider.on('chainChanged', handleChain);

      return () => {
        if (provider.removeListener) {
          provider.removeListener('accountsChanged', handleAccounts);
          provider.removeListener('chainChanged', handleChain);
        }
      };
    }
  }, []);

  // Convert GitHub/Gist URL to raw URLs to bypass basic CORS restrictions
  const getRawUrl = (url: string): string => {
    if (!url) return '';
    let rawUrl = url.trim();
    if (url.includes('github.com') && !url.includes('raw.githubusercontent.com')) {
      rawUrl = url
        .replace('github.com', 'raw.githubusercontent.com')
        .replace('/blob/', '/');
    }
    return rawUrl;
  };

  // Calculate SHA-256 hash of a string using Web Crypto API
  const calculateSHA256 = async (text: string): Promise<string> => {
    try {
      const msgBuffer = new TextEncoder().encode(text);
      const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (e) {
      console.error('Hash error:', e);
      return '';
    }
  };

  // Fetch raw files from URLs for R1CS visualizer
  const fetchFileContent = async (url: string): Promise<string> => {
    if (!url) return '';
    try {
      const raw = getRawUrl(url);
      const res = await fetch(raw);
      if (res.ok) {
        return await res.text();
      }
    } catch (e) {
      console.error('Fetch error:', e);
    }
    return '';
  };

  // Auto-fetch and calculate target circuit hash on URL change
  useEffect(() => {
    if (newCircuitUrl && newCircuitUrl.startsWith('http')) {
      fetchFileContent(newCircuitUrl).then(async (content) => {
        if (content) {
          const hash = await calculateSHA256(content);
          setNewCircuitHash(hash);
          addLog(`[UI] Auto-computed target circuit SHA-256: ${hash}`);
        }
      });
    }
  }, [newCircuitUrl]);

  // Auto-fetch and calculate exploit witness hash on URL change
  useEffect(() => {
    if (exploitUrl && exploitUrl.startsWith('http')) {
      fetchFileContent(exploitUrl).then(async (content) => {
        if (content) {
          const hash = await calculateSHA256(content);
          setExploitHash(hash);
          addLog(`[UI] Auto-computed exploit witness SHA-256: ${hash}`);
        }
      });
    }
  }, [exploitUrl]);

  // Load selected task files
  const activeTask = tasks.find(t => t.id === selectedTaskId);
  useEffect(() => {
    if (!activeTask) {
      setCircuitCode('// Select a task to load circuit code');
      setExploitCode('// Select a task to load exploit witness');
      return;
    }

    setCircuitCode('// Fetching circuit code from: ' + activeTask.circuit_url + ' ...');
    setExploitCode(activeTask.proof_of_exploit_url 
      ? '// Fetching exploit witness from: ' + activeTask.proof_of_exploit_url + ' ...'
      : '// No exploit witness submitted yet.');

    fetchFileContent(activeTask.circuit_url).then(code => {
      setCircuitCode(code || `// Target URL: ${activeTask.circuit_url}\n// (Unable to fetch raw code directly. Please verify URL or check CORS headers.)`);
    });

    if (activeTask.proof_of_exploit_url) {
      fetchFileContent(activeTask.proof_of_exploit_url).then(code => {
        setExploitCode(code || `// Exploit URL: ${activeTask.proof_of_exploit_url}\n// (Unable to fetch raw code directly. Please verify URL or check CORS headers.)`);
      });
    }
  }, [selectedTaskId, tasks]);

  // Connect Wallet
  const connectWallet = async () => {
    if (typeof window === 'undefined' || !(window as any).ethereum) {
      alert('MetaMask or another EIP-1193 wallet was not detected in your browser.');
      addLog('[WALLET ERROR] EIP-1193 provider missing from browser.');
      return;
    }

    try {
      setIsLoading(true);
      addLog('[WALLET] Requesting provider credentials...');
      const provider = (window as any).ethereum;
      
      // Prompt MetaMask to switch to Studionet (Chain ID 61999 / 0xf22f)
      try {
        await provider.request({
          method: 'wallet_switchEthereumChain',
          params: [{ chainId: '0xf22f' }],
        });
      } catch (switchError: any) {
        if (switchError.code === 4902) {
          try {
            await provider.request({
              method: 'wallet_addEthereumChain',
              params: [
                {
                  chainId: '0xf22f',
                  chainName: 'GenLayer StudioNet',
                  rpcUrls: ['https://studio.genlayer.com/api'],
                  nativeCurrency: {
                    name: 'GEN',
                    symbol: 'GEN',
                    decimals: 18,
                  },
                  blockExplorerUrls: [],
                },
              ],
            });
          } catch (addError) {
            console.error('Error adding network:', addError);
          }
        }
      }

      const accounts = await provider.request({ method: 'eth_requestAccounts' });
      
      const client = createClient({
        chain: studionet,
        account: accounts[0] as `0x${string}`,
        provider: provider,
        endpoint: 'https://studio.genlayer.com/api'
      });
      
      setGenlayerClient(client);
      setWalletAddress(accounts[0]);
      setWalletConnected(true);
      setWalletBalance('12.5k'); // Display generic balance indicator
      
      localStorage.setItem('wallet_previously_connected', 'true');
      
      addLog(`[WALLET] Wallet successfully connected to Studionet. Address: ${accounts[0]}`);
      await fetchTasksFromContract();
    } catch (err: any) {
      console.error(err);
      addLog(`[WALLET ERROR] Connection failed: ${err.message || err}`);
    } finally {
      setIsLoading(false);
    }
  };

  // Disconnect Wallet
  const disconnectWallet = () => {
    setWalletConnected(false);
    setWalletAddress('');
    setGenlayerClient(null);
    localStorage.removeItem('wallet_previously_connected');
    addLog('[WALLET] Wallet disconnected.');
  };

  // Fetch tasks from deployed contract on-chain
  const fetchTasksFromContract = async () => {
    try {
      setIsLoading(true);
      addLog('[CONTRACT] Instantiating on-chain read client...');
      
      // Instantiate read client to read states even if no wallet is connected
      const client = createClient({
        chain: studionet,
        endpoint: 'https://studio.genlayer.com/api'
      });
      
      addLog(`[CONTRACT] Reading get_all_tasks() from ${contractAddress}...`);
      const res = await client.readContract({
        address: contractAddress as `0x${string}`,
        functionName: 'get_all_tasks',
        args: []
      });
      
      const parsedTasks = JSON.parse(res as string);
      if (Array.isArray(parsedTasks)) {
        setTasks(parsedTasks);
        addLog(`[CONTRACT] Successfully retrieved ${parsedTasks.length} tasks from chain.`);
        
        // Auto select first task if none is selected
        if (parsedTasks.length > 0 && !selectedTaskId) {
          setSelectedTaskId(parsedTasks[0].id);
        }
      }
    } catch (err: any) {
      console.error(err);
      addLog(`[CONTRACT ERROR] Read contract failed: ${err.message || err}`);
      setTasks([]);
    } finally {
      setIsLoading(false);
    }
  };

  // Helper parsing decimals to bigints safely
  const parseUnits = (amount: string, decimals: number = 18): bigint => {
    try {
      const parts = amount.split('.');
      let integer = parts[0] || '0';
      let fraction = parts[1] || '';
      fraction = fraction.padEnd(decimals, '0').slice(0, decimals);
      return BigInt(integer + fraction);
    } catch {
      return 0n;
    }
  };

  // Helper formatting bigints
  const formatGenAmount = (weiStr: string) => {
    try {
      if (!weiStr || weiStr === '0') return '0';
      if (weiStr.length > 18) {
        const integer = weiStr.slice(0, -18) || '0';
        const fraction = weiStr.slice(-18).slice(0, 4); // Display up to 4 decimal places
        const formatted = `${integer}.${fraction}`.replace(/\.?0+$/, '');
        return `${formatted} GEN`;
      } else {
        const decimals = parseFloat(weiStr) / 1e18;
        return `${decimals} GEN`;
      }
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

  // Action: Create Bounty (payable)
  const handleCreateBounty = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTaskId || !newCircuitUrl || !newCircuitHash || !newFocus || !newProjectName) {
      alert('Please fill out all fields (including the target circuit hash).');
      return;
    }

    if (!walletConnected || !genlayerClient) {
      alert('Please connect your wallet first.');
      return;
    }

    const valueWei = parseUnits(newEscrowAmount);
    
    // Construct rich string representations to fit smart contract arguments
    const circuit_framework = `${newFramework} ${newCompilerVersion} / ${newProvingSystem}`;
    const constraint_focus = `${newFocus} (Complexity: ${newComplexity})`;

    try {
      setIsLoading(true);
      addLog(`[CHAIN TX] Invoking create_audit_bounty(${newTaskId}) with ${newEscrowAmount} GEN deposit...`);
      
      const hash = await genlayerClient.writeContract({
        address: contractAddress as `0x${string}`,
        functionName: 'create_audit_bounty',
        args: [newTaskId, newCircuitUrl, newCircuitHash, circuit_framework, constraint_focus],
        value: valueWei
      });
      
      addLog(`[CHAIN TX] Broadcasted. Hash: ${hash}. Waiting for receipt confirmation...`);
      
      try {
        await Promise.race([
          genlayerClient.waitForTransactionReceipt({ hash }),
          new Promise((_, reject) => setTimeout(() => reject(new Error('Timeout waiting for transaction finalization')), 15000))
        ]);
        addLog(`[CHAIN CONFIRMED] Transaction finalized. Bounty created.`);
      } catch (receiptError: any) {
        console.error(receiptError);
        addLog(`[CHAIN WARNING] ${receiptError.message || receiptError}. Checking tasks soon...`);
      }
      
      setShowCreateModal(false);
      
      // Clear forms
      setNewProjectName('');
      setNewTaskId('');
      setNewCircuitUrl('');
      setNewCircuitHash('');
      setNewFocus('');
      
      // Short delay for RPC indexer synchronization
      await new Promise(resolve => setTimeout(resolve, 2000));
      await fetchTasksFromContract();
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
    if (!walletConnected || !genlayerClient) {
      alert('Connect wallet first.');
      return;
    }

    const requiredStake = String(BigInt(activeTask.escrow_amount) / BigInt(5)); // 20%

    try {
      setIsLoading(true);
      addLog(`[CHAIN TX] Invoking accept_audit_task for task ${activeTask.id}. Staking 20% (${parseFloat(requiredStake)/1e18} GEN)...`);
      
      const hash = await genlayerClient.writeContract({
        address: contractAddress as `0x${string}`,
        functionName: 'accept_audit_task',
        args: [activeTask.id],
        value: BigInt(requiredStake)
      });
      
      addLog(`[CHAIN TX] Sent. Hash: ${hash}. Finalizing...`);
      try {
        await Promise.race([
          genlayerClient.waitForTransactionReceipt({ hash }),
          new Promise((_, r) => setTimeout(() => r(new Error('Timeout waiting for finalization')), 12000))
        ]);
        addLog(`[CHAIN CONFIRMED] Stake deposit success. Locked task.`);
      } catch (e: any) {
        addLog(`[CHAIN WARNING] Stake transaction sent. Check task status soon.`);
      }
      
      await new Promise(r => setTimeout(r, 2000));
      await fetchTasksFromContract();
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
    if (!activeTask || !exploitUrl || !exploitHash) {
      alert('Please provide both the exploit URL and its corresponding SHA-256 hash.');
      return;
    }
    if (!walletConnected || !genlayerClient) {
      alert('Connect wallet first.');
      return;
    }

    try {
      setIsLoading(true);
      addLog(`[CHAIN TX] Submitting counterexample witness to ${activeTask.id}...`);
      
      const hash = await genlayerClient.writeContract({
        address: contractAddress as `0x${string}`,
        functionName: 'submit_counterexample',
        args: [activeTask.id, exploitUrl, exploitHash]
      });
      
      addLog(`[CHAIN TX] Sent. Hash: ${hash}. AI consensus evaluating counterexample. Please wait...`);
      try {
        await Promise.race([
          genlayerClient.waitForTransactionReceipt({ hash }),
          new Promise((_, r) => setTimeout(() => r(new Error('Timeout waiting for finalization')), 15000))
        ]);
        addLog(`[CHAIN CONFIRMED] Witness evaluated on-chain.`);
      } catch (e: any) {
        addLog(`[CHAIN WARNING] Exploit submitted. AI Consensus running in background.`);
      }
      setExploitUrl('');
      setExploitHash('');
      await new Promise(r => setTimeout(r, 2000));
      await fetchTasksFromContract();
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
    if (!walletConnected || !genlayerClient) {
      alert('Connect wallet first.');
      return;
    }

    try {
      setIsLoading(true);
      addLog(`[CHAIN TX] Raising dispute on ${activeTask.id}: "${disputeReason}"...`);
      
      const hash = await genlayerClient.writeContract({
        address: contractAddress as `0x${string}`,
        functionName: 'raise_dispute',
        args: [activeTask.id, disputeReason]
      });
      
      try {
        await Promise.race([
          genlayerClient.waitForTransactionReceipt({ hash }),
          new Promise((_, r) => setTimeout(() => r(new Error('Timeout waiting for finalization')), 12000))
        ]);
        addLog(`[CHAIN CONFIRMED] Dispute successfully registered.`);
      } catch (e) {
        addLog(`[CHAIN WARNING] Dispute transaction sent.`);
      }
      setDisputeReason('');
      await new Promise(r => setTimeout(r, 2000));
      await fetchTasksFromContract();
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
    if (!walletConnected || !genlayerClient) {
      alert('Connect wallet first.');
      return;
    }

    try {
      setIsLoading(true);
      addLog(`[CHAIN TX] Invoking finalize_payout for task ${activeTask.id}...`);
      
      const hash = await genlayerClient.writeContract({
        address: contractAddress as `0x${string}`,
        functionName: 'finalize_payout',
        args: [activeTask.id]
      });
      
      try {
        await Promise.race([
          genlayerClient.waitForTransactionReceipt({ hash }),
          new Promise((_, r) => setTimeout(() => r(new Error('Timeout waiting for finalization')), 12000))
        ]);
        addLog(`[CHAIN CONFIRMED] Payout finalized and disbursed.`);
      } catch (e) {
        addLog(`[CHAIN WARNING] Finalization transaction sent.`);
      }
      await new Promise(r => setTimeout(r, 2000));
      await fetchTasksFromContract();
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
    if (!walletConnected || !genlayerClient) {
      alert('Connect wallet first.');
      return;
    }

    try {
      setIsLoading(true);
      addLog(`[CHAIN TX] Resolving escalation for ${activeTask.id} with action ${arbitrationAction}...`);
      
      const hash = await genlayerClient.writeContract({
        address: contractAddress as `0x${string}`,
        functionName: 'resolve_escalation',
        args: [activeTask.id, arbitrationAction]
      });
      
      try {
        await Promise.race([
          genlayerClient.waitForTransactionReceipt({ hash }),
          new Promise((_, r) => setTimeout(() => r(new Error('Timeout waiting for finalization')), 12000))
        ]);
        addLog(`[CHAIN CONFIRMED] Escalation resolved.`);
      } catch (e) {
        addLog(`[CHAIN WARNING] Escalation transaction sent.`);
      }
      await new Promise(r => setTimeout(r, 2000));
      await fetchTasksFromContract();
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
          {/* Refresh onchain state */}
          <button
            onClick={fetchTasksFromContract}
            disabled={isLoading}
            className="p-2 bg-slate-950 border border-purple-950/40 rounded text-slate-400 hover:text-purple-300 transition duration-150 flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
            title="Refresh On-Chain State"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span className="text-[10px] font-bold">Refresh</span>
          </button>

          {/* Contract Address Config */}
          <div className="flex items-center bg-slate-950 border border-purple-950/40 rounded px-2.5 py-1.5">
            <Settings className="w-3.5 h-3.5 text-slate-500 mr-2" />
            <span className="text-slate-500 mr-1.5 text-[10px]">CONTRACT:</span>
            <input
              type="text"
              value={contractAddress}
              onChange={(e) => setContractAddress(e.target.value.trim())}
              autoComplete="off"
              spellCheck={false}
              className="bg-transparent text-[11px] text-purple-300 font-mono focus:outline-none w-28 text-ellipsis border-b border-transparent focus:border-purple-600"
            />
          </div>

          {/* Connected wallet panel */}
          {walletConnected ? (
            <div className="flex items-center gap-3 bg-slate-950/90 border border-emerald-950 rounded pl-3 pr-1 py-1 text-xs">
              <div className="flex items-center gap-1.5">
                <div className="w-2 h-2 rounded-full bg-emerald-400 glow-mint animate-pulse"></div>
                <span className="text-slate-400 font-mono truncate max-w-[100px]" title={walletAddress}>{walletAddress}</span>
              </div>
              <span className="text-emerald-400 font-bold border-l border-slate-900 pl-2">Studionet ({walletBalance})</span>
              <button 
                onClick={disconnectWallet}
                className="px-2.5 py-1 bg-rose-950/60 hover:bg-rose-900 border border-rose-800/40 hover:border-rose-600 text-rose-300 rounded text-[10px] font-bold transition flex items-center gap-1 cursor-pointer"
              >
                <LogOut className="w-3 h-3" /> Disconnect
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
                <Activity className="w-4 h-4 text-purple-400" /> Consensus Telemetry HUD
              </h2>
              <span className="text-[10px] text-emerald-400 flex items-center gap-1">
                <span className="w-1.5 h-1.5 bg-emerald-400 rounded-full animate-pulse"></span> Active
              </span>
            </div>

            {/* Steps HUD */}
            <div className="flex flex-col gap-2.5 text-[11px] font-mono">
              {[
                { name: 'Circuit AST Ingestion', desc: 'Verify compiler source structure on-chain.' },
                { name: 'Signal Constraint Degree Check', desc: 'Consensus checking degree coefficient equations.' },
                { name: 'Witness Inversion Validation', desc: 'Mathematical validation of submitted witness script.' },
                { name: 'Consensus Escrow Release', desc: 'AI agreement on mathematical correctness verdict.' }
              ].map((step, idx) => {
                // Since this runs entirely on-chain now, we derive status directly from active task state.
                const isActive = activeTask && activeTask.status === 'IN_PROGRESS';
                const isPassed = activeTask && ['AWAITING_PAYOUT', 'DISPUTED', 'CLOSED'].includes(activeTask.status);

                return (
                  <div 
                    key={idx} 
                    className={`p-2 border rounded transition duration-300 ${
                      isActive 
                        ? 'border-amber-500 bg-amber-950/20 text-amber-300' 
                        : isPassed 
                          ? 'border-purple-950 bg-purple-950/10 text-purple-400' 
                          : 'border-slate-900 bg-slate-900/10 text-slate-600'
                    }`}
                  >
                    <div className="flex items-center justify-between font-bold mb-0.5">
                      <span>[{idx + 1}] {step.name}</span>
                      {isActive ? (
                        <span className="text-[9px] px-1 py-0.5 bg-amber-900/40 text-amber-300 border border-amber-500/50 rounded animate-pulse">
                          VERIFYING
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
                <Layers className="w-4 h-4 text-purple-400" /> On-Chain Bounties
              </h2>
              <button 
                onClick={() => {
                  if (!walletConnected) {
                    alert('Please connect your wallet first.');
                    return;
                  }
                  setShowCreateModal(true);
                }}
                className="px-2.5 py-1.5 bg-purple-900/60 hover:bg-purple-800/80 border border-purple-700/40 text-purple-200 rounded text-[10px] flex items-center gap-1 transition cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" /> Publish
              </button>
            </div>

            {/* List */}
            <div className="flex-1 overflow-y-auto max-h-[350px] xl:max-h-none flex flex-col gap-2">
              {tasks.length === 0 ? (
                <div className="text-center py-12 text-xs text-slate-600 border border-dashed border-slate-900 rounded font-mono">
                  No bounty tasks found.<br />Check contract address or deploy a task.
                </div>
              ) : (
                tasks.map(task => {
                  const isSelected = task.id === selectedTaskId;
                  
                  // Status colors
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
                          <span className="text-slate-400">{task.circuit_framework.split(' ')[0]}</span>
                        </div>
                        <div className="text-right">
                          <span className="text-slate-600 mr-1">DEPOSIT:</span>
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
                      Circuit Repo: <a href={activeTask.circuit_url} target="_blank" rel="noreferrer" className="text-purple-400 hover:underline break-all">{activeTask.circuit_url}</a>
                    </p>
                  </div>
                  
                  {/* Status Box */}
                  <div className="flex items-center gap-3">
                    <div className="bg-slate-900 border border-purple-950 px-3 py-1.5 rounded text-xs flex flex-col items-center">
                      <span className="text-[9px] text-slate-500 font-bold tracking-wider">BOUNTY ESCROW</span>
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
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
                  <div className="p-3 bg-slate-900/60 border border-slate-900 rounded">
                    <span className="text-[10px] text-slate-500 block mb-1 font-bold">FRAMEWORK / COMPILER</span>
                    <span className="text-slate-300">{activeTask.circuit_framework}</span>
                  </div>
                  <div className="p-3 bg-slate-900/60 border border-slate-900 rounded md:col-span-2">
                    <span className="text-[10px] text-slate-500 block mb-1 font-bold">CONSTRAINT TARGET FOCUS</span>
                    <span className="text-amber-300">{activeTask.constraint_focus}</span>
                  </div>
                </div>

                {/* Cryptographic pinned artifacts (SHA-256) */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                  <div className="p-3 bg-slate-900/60 border border-slate-900 rounded">
                    <span className="text-[10px] text-slate-500 block mb-1 font-bold">PINNED TARGET CIRCUIT SHA-256</span>
                    <span className="text-purple-300 select-all break-all">{activeTask.circuit_hash || 'N/A'}</span>
                  </div>
                  <div className="p-3 bg-slate-900/60 border border-slate-900 rounded">
                    <span className="text-[10px] text-slate-500 block mb-1 font-bold">PINNED EXPLOIT WITNESS SHA-256</span>
                    <span className="text-amber-300 select-all break-all">{activeTask.exploit_hash || 'Awaiting Auditor Submission'}</span>
                  </div>
                </div>

                {/* Consensus Pipeline Verdict Section */}
                {activeTask.verdict !== 'NONE' && (
                  <div className={`p-4 border rounded text-xs font-mono ${
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
                        <p className="text-slate-300 leading-relaxed italic mt-0.5">
                          "{activeTask.reason}"
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {/* 24h Countdown & Dispute Banner */}
                {activeTask.status === 'AWAITING_PAYOUT' && (
                  <div className="p-4 bg-amber-950/15 border border-amber-900/60 rounded flex flex-col md:flex-row md:items-center justify-between gap-4 font-mono">
                    <div className="flex items-start gap-3">
                      <Clock className="w-5 h-5 text-amber-400 mt-0.5 animate-pulse" />
                      <div>
                        <span className="text-xs font-bold text-amber-300 block tracking-wider uppercase">
                          24h Challenge Window Active
                        </span>
                        <p className="text-[11px] text-slate-400 mt-1 leading-normal max-w-xl">
                          On-chain consensus has verified this exploit. Escrow release is currently locked in a cooling-off window. The project owner or auditor can raise a dispute if incorrect.
                        </p>
                      </div>
                    </div>
                    
                    <div className="flex items-center gap-4">
                      <div className="text-center md:text-right bg-slate-950 border border-amber-950 px-3.5 py-1.5 rounded">
                        <span className="text-[9px] text-slate-500 block font-bold">CHALLENGE TIMEOUT</span>
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
                      <FileCode className="w-4 h-4 text-purple-400" /> R1CS / PlonKish Constraint Visualizer
                    </h3>
                    <p className="text-[10px] text-slate-500 mt-0.5">Dual-pane code analysis loaded directly from source endpoints</p>
                  </div>
                  
                  <span className="text-[10px] text-purple-400 px-2.5 py-1 bg-purple-950/30 border border-purple-900/40 rounded font-mono">
                    {activeTask.circuit_framework}
                  </span>
                </div>

                {/* Dual-Pane Editor */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  
                  {/* Left Pane: Original Circuit */}
                  <div className="border border-purple-950/50 bg-slate-950 rounded overflow-hidden flex flex-col h-[280px]">
                    <div className="bg-purple-950/20 px-3 py-1.5 border-b border-purple-950/60 flex items-center justify-between text-[11px] font-bold text-purple-300 font-mono">
                      <span>Target Circuit Code</span>
                      <span className="text-[9px] text-slate-500 font-mono font-normal">SOURCE URL</span>
                    </div>
                    <textarea
                      readOnly
                      value={circuitCode}
                      className="flex-1 p-3 text-[11px] font-mono bg-slate-950 text-slate-400 focus:outline-none resize-none overflow-y-auto leading-relaxed border-none"
                    />
                  </div>

                  {/* Right Pane: PoC Exploit Witness */}
                  <div className="border border-purple-950/50 bg-slate-950 rounded overflow-hidden flex flex-col h-[280px]">
                    <div className="bg-purple-950/20 px-3 py-1.5 border-b border-purple-950/60 flex items-center justify-between text-[11px] font-bold text-amber-300 font-mono">
                      <span>PoC Witness / Counterexample</span>
                      <span className="text-[9px] text-slate-500 font-mono font-normal">AUDITOR URL</span>
                    </div>
                    <textarea
                      readOnly
                      value={exploitCode}
                      className="flex-1 p-3 text-[11px] font-mono bg-slate-950 text-amber-200/90 focus:outline-none resize-none overflow-y-auto leading-relaxed border-none"
                    />
                  </div>

                </div>
              </section>

              {/* Action Console depending on Role */}
              <section className="bg-slate-950/90 border border-purple-950/70 rounded p-5 flex flex-col gap-4">
                {/* Role Toggle Selector */}
                <div className="flex items-center justify-between border-b border-purple-950/60 pb-3">
                  <div className="flex items-center gap-1.5 font-mono">
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
                        className={`text-[10px] px-3 py-1.5 border rounded transition cursor-pointer ${
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
                    <div className="flex flex-col gap-4 font-mono">
                      {activeTask.status === 'OPEN' && (
                        <p className="text-slate-400 italic">
                          Awaiting an independent ZK Auditor to stake 20% security deposit ({(parseFloat(activeTask.escrow_amount) / 1e18) * 0.2} GEN) and lock this contract on-chain.
                        </p>
                      )}

                      {activeTask.status === 'IN_PROGRESS' && (
                        <p className="text-slate-400">
                          Auditor <span className="font-mono text-purple-400">{activeTask.auditor}</span> has locked this bounty and is currently verifying target constraints.
                        </p>
                      )}

                      {activeTask.status === 'AWAITING_PAYOUT' && (
                        <div className="flex flex-col gap-4">
                          <p className="text-slate-300">
                            The solver verification passed. If you believe the auditor's PoC is invalid or out of scope, challenge it within the 24h cooldown. Otherwise, disburse.
                          </p>
                          <form onSubmit={handleRaiseDispute} className="flex flex-wrap gap-3 items-end">
                            <div className="flex-1 min-w-[280px]">
                              <label className="text-[10px] text-slate-500 block font-bold mb-1">DISPUTE CHALLENGE JUSTIFICATION</label>
                              <input
                                type="text"
                                required
                                value={disputeReason}
                                onChange={(e) => setDisputeReason(e.target.value)}
                                placeholder="State reason (e.g., witness uses out of scope parameters...)"
                                className="w-full bg-slate-950 border border-purple-950/80 rounded p-2 text-xs font-mono focus:outline-none focus:border-purple-600"
                              />
                            </div>
                            <button
                              type="submit"
                              disabled={isLoading || !walletConnected}
                              className="px-4 py-2 bg-rose-950 hover:bg-rose-900 border border-rose-800 hover:border-rose-600 text-rose-200 rounded font-bold transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                            >
                              <AlertTriangle className="w-4 h-4 text-rose-400" /> Raise Dispute
                            </button>
                            
                            {/* Finalize button - only available if time expired */}
                            <button
                              type="button"
                              onClick={handleFinalizePayout}
                              disabled={isLoading || !walletConnected || (timeRemaining[activeTask.id] !== 0)}
                              className="px-4 py-2 bg-emerald-950 hover:bg-emerald-900 border border-emerald-800 hover:border-emerald-600 text-emerald-200 rounded font-bold transition flex items-center gap-1.5 cursor-pointer disabled:opacity-40"
                              title={timeRemaining[activeTask.id] !== 0 ? "Cooling off period must elapse first" : ""}
                            >
                              <CheckCircle className="w-4 h-4 text-emerald-400" /> Finalize Payout
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
                    <div className="flex flex-col gap-4 font-mono">
                      {activeTask.status === 'OPEN' && (
                        <div className="flex flex-col gap-3">
                          <p className="text-slate-300">
                            Lock this bounty to submit a witness file counterexample. Staking 20% security deposit ({(parseFloat(activeTask.escrow_amount) / 1e18) * 0.2} GEN) is required.
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
                              <span className="text-[10px] text-rose-400 mt-1 block">Connect your wallet to execute staking transaction.</span>
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
                          
                          <form onSubmit={handleSubmitCounterexample} className="flex flex-col gap-3">
                            <div className="w-full">
                              <label className="text-[10px] text-slate-500 block font-bold mb-1">POC / WITNESS EXPLOIT URL</label>
                              <input
                                type="url"
                                required
                                value={exploitUrl}
                                onChange={(e) => setExploitUrl(e.target.value)}
                                placeholder="https://github.com/zk-exploit/fake_witness.js"
                                className="w-full bg-slate-950 border border-purple-950/80 rounded p-2 text-xs font-mono focus:outline-none focus:border-purple-600"
                              />
                            </div>
                            <div className="w-full">
                              <label className="text-[10px] text-slate-500 block font-bold mb-1">EXPLOIT WITNESS SHA-256 HASH (AUTO-CALCULATED ON URL INPUT)</label>
                              <input
                                type="text"
                                required
                                value={exploitHash}
                                onChange={(e) => setExploitHash(e.target.value)}
                                placeholder="e.g. 5f4dcc3b5aa765d61d8327deb882cf99..."
                                className="w-full bg-slate-950 border border-purple-950/80 rounded p-2 text-xs font-mono focus:outline-none focus:border-purple-600"
                              />
                            </div>
                            <div className="flex justify-end">
                              <button
                                type="submit"
                                disabled={isLoading || !walletConnected}
                                className="px-5 py-2 bg-emerald-950 hover:bg-emerald-900 border border-emerald-800 hover:border-emerald-600 text-emerald-200 rounded font-bold transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                              >
                                {isLoading ? (
                                  <>
                                    <RefreshCw className="w-4 h-4 animate-spin text-emerald-400" /> Processing...
                                  </>
                                ) : (
                                  <>
                                    <Play className="w-4 h-4 text-emerald-400" /> Submit Exploit URL & Hash
                                  </>
                                )}
                              </button>
                            </div>
                          </form>
                          {!walletConnected && (
                            <span className="text-[10px] text-rose-400 block">Connect your wallet to submit.</span>
                          )}
                        </div>
                      )}

                      {activeTask.status === 'AWAITING_PAYOUT' && (
                        <div className="flex flex-col gap-3">
                          <p className="text-emerald-400 font-bold flex items-center gap-1.5">
                            <CheckCircle className="w-4 h-4 text-emerald-400" /> Your exploit counterexample was approved. Finalize window ends in {formatDuration(timeRemaining[activeTask.id] || 0)}.
                          </p>
                          <button
                            type="button"
                            onClick={handleFinalizePayout}
                            disabled={isLoading || !walletConnected || (timeRemaining[activeTask.id] !== 0)}
                            className="px-4 py-2 bg-emerald-950 hover:bg-emerald-900 border border-emerald-800 hover:border-emerald-600 text-emerald-200 rounded font-bold transition flex items-center gap-1.5 cursor-pointer self-start disabled:opacity-40"
                          >
                            <CheckCircle className="w-4 h-4 text-emerald-400" /> Finalize Release Payout
                          </button>
                        </div>
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
                    <div className="flex flex-col gap-4 font-mono">
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
                                  className={`text-[10px] px-3 py-1.5 border rounded transition cursor-pointer ${
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
                              disabled={isLoading || !walletConnected}
                              className="px-4 py-1.5 bg-emerald-950 hover:bg-emerald-900 border border-emerald-800 text-emerald-300 rounded font-bold transition flex items-center gap-1 cursor-pointer disabled:opacity-50"
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
            <div className="bg-slate-950/90 border border-purple-950/70 rounded p-12 text-center text-slate-500 text-sm font-mono">
              Please select or create an audit task from the sidebar.
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
          <div className="bg-[#08080C] border border-purple-950 rounded-lg max-w-lg w-full p-6 relative shadow-2xl overflow-y-auto max-h-[90vh]">
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
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] text-slate-500 block mb-1 font-bold">PROJECT NAME</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g., ZK Bridge Rollup"
                    value={newProjectName}
                    onChange={(e) => setNewProjectName(e.target.value)}
                    className="w-full bg-slate-950 border border-purple-950 rounded p-2 text-slate-300 focus:outline-none focus:border-purple-600"
                  />
                </div>
                <div>
                  <label className="text-[10px] text-slate-500 block mb-1 font-bold">TASK ID (EDITABLE)</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g., zk_bridge_rollup_123"
                    value={newTaskId}
                    onChange={(e) => setNewTaskId(e.target.value)}
                    className="w-full bg-slate-950 border border-purple-950 rounded p-2 text-slate-300 focus:outline-none focus:border-purple-600"
                  />
                </div>
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

              <div>
                <label className="text-[10px] text-slate-500 block mb-1 font-bold">TARGET CIRCUIT SHA-256 HASH (AUTO-CALCULATED ON URL INPUT)</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 5f4dcc3b5aa765d61d8327deb882cf99..."
                  value={newCircuitHash}
                  onChange={(e) => setNewCircuitHash(e.target.value)}
                  className="w-full bg-slate-950 border border-purple-950 rounded p-2 text-slate-300 focus:outline-none focus:border-purple-600 font-mono text-[11px]"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] text-slate-500 block mb-1 font-bold">FRAMEWORK TYPE</label>
                  <select
                    value={newFramework}
                    onChange={(e) => setNewFramework(e.target.value)}
                    className="w-full bg-slate-950 border border-purple-950 rounded p-2 text-slate-300 focus:outline-none focus:border-purple-600"
                  >
                    <option>Circom</option>
                    <option>Halo2</option>
                    <option>Noir</option>
                    <option>Plonky2</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] text-slate-500 block mb-1 font-bold">COMPILER VERSION</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g., v2.1.6 or v0.33.0"
                    value={newCompilerVersion}
                    onChange={(e) => setNewCompilerVersion(e.target.value)}
                    className="w-full bg-slate-950 border border-purple-950 rounded p-2 text-slate-300 focus:outline-none focus:border-purple-600"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] text-slate-500 block mb-1 font-bold">PROVING SYSTEM</label>
                  <select
                    value={newProvingSystem}
                    onChange={(e) => setNewProvingSystem(e.target.value)}
                    className="w-full bg-slate-950 border border-purple-950 rounded p-2 text-slate-300 focus:outline-none focus:border-purple-600"
                  >
                    <option>Groth16</option>
                    <option>PLONK</option>
                    <option>PlonKish</option>
                    <option>Honk</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] text-slate-500 block mb-1 font-bold">COMPLEXITY / GATE COUNT</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g., 15k gates or 2^18 constraints"
                    value={newComplexity}
                    onChange={(e) => setNewComplexity(e.target.value)}
                    className="w-full bg-slate-950 border border-purple-950 rounded p-2 text-slate-300 focus:outline-none focus:border-purple-600"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 gap-3">
                <div>
                  <label className="text-[10px] text-slate-500 block mb-1 font-bold">ESCROW DEPOSIT AMOUNT (GEN)</label>
                  <input
                    type="number"
                    min="0.0001"
                    step="any"
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
                  className="px-4 py-2 border border-slate-900 hover:border-slate-800 rounded font-semibold text-slate-400 transition cursor-pointer"
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
