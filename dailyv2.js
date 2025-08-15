
import chalk from "chalk";
import { ethers } from "ethers";
import fs from "fs";
import { HttpsProxyAgent } from "https-proxy-agent";
import { SocksProxyAgent } from "socks-proxy-agent";
import axios from "axios";
import { Web3 } from "web3";

// Configuration
const RPC_URL = "https://testnet1.helioschainlabs.org/";
const TOKEN_ADDRESS = "0xD4949664cD82660AaE99bEdc034a0deA8A0bd517";
const BRIDGE_ROUTER_ADDRESS = "0x0000000000000000000000000000000000000900";
const STAKE_ROUTER_ADDRESS = "0x0000000000000000000000000000000000000800";
const CHAIN_ID = 42000;

// Faucet Configuration
const FAUCET_CONFIG = {
  rpcUrl: 'https://testnet1.helioschainlabs.org',
  apiBaseUrl: 'https://testnet-api.helioschain.network/api',
  currencySymbol: 'HELIOS'
};

let privateKeys = [];
let proxies = [];
let nonceTracker = {};

// Auto configuration
const autoConfig = {
  bridgeRepetitions: 3,
  minHlsBridge: 0.001,
  maxHlsBridge: 0.005,
  stakeRepetitions: 3,
  minHlsStake: 0.01,
  maxHlsStake: 0.05,
  loopInterval: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
  delayBetweenAccounts: 10000, // 10 seconds between accounts
  delayBetweenActions: 5000 // 5 seconds between actions
};

// Statistics tracking
let dailyStats = {
  totalAccounts: 0,
  successfulAccounts: 0,
  failedAccounts: 0,
  totalBridges: 0,
  successfulBridges: 0,
  failedBridges: 0,
  totalStakes: 0,
  successfulStakes: 0,
  failedStakes: 0,
  totalHlsBridged: 0,
  totalHlsStaked: 0,
  faucetClaims: 0,
  faucetClaimFails: 0,
  startTime: null,
  endTime: null,
  errors: []
};

// Utility functions
function log(message, type = "info") {
  const timestamp = new Date().toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const coloredTimestamp = chalk.gray(`[${timestamp}]`);
  
  let coloredMessage;
  switch (type) {
    case "error":
      coloredMessage = chalk.redBright(message);
      break;
    case "success":
      coloredMessage = chalk.greenBright(message);
      break;
    case "wait":
      coloredMessage = chalk.yellowBright(message);
      break;
    case "info":
      coloredMessage = chalk.whiteBright(message);
      break;
    case "faucet":
      coloredMessage = chalk.blueBright(message);
      break;
    default:
      coloredMessage = chalk.white(message);
  }
  
  console.log(`${coloredTimestamp} ${coloredMessage}`);
}

function getShortAddress(address) {
  return address ? address.slice(0, 6) + "..." + address.slice(-4) : "N/A";
}

function getShortHash(hash) {
  return hash ? hash.slice(0, 6) + "..." + hash.slice(-4) : "N/A";
}

function getShortProxy(proxy) {
  if (!proxy) return "N/A";
  const parts = proxy.split('@');
  return parts.length > 1 ? parts[1] : proxy;
}

function resetDailyStats() {
  dailyStats = {
    totalAccounts: 0,
    successfulAccounts: 0,
    failedAccounts: 0,
    totalBridges: 0,
    successfulBridges: 0,
    failedBridges: 0,
    totalStakes: 0,
    successfulStakes: 0,
    failedStakes: 0,
    totalHlsBridged: 0,
    totalHlsStaked: 0,
    faucetClaims: 0,
    faucetClaimFails: 0,
    startTime: null,
    endTime: null,
    errors: []
  };
}

function formatDuration(ms) {
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  
  if (hours > 0) {
    return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
  } else if (minutes > 0) {
    return `${minutes}m ${seconds % 60}s`;
  } else {
    return `${seconds}s`;
  }
}

function displaySummary() {
  console.log("");
  console.log(chalk.yellow(`⏰ Next cycle will start in ${formatDuration(autoConfig.loopInterval)} at ${new Date(Date.now() + autoConfig.loopInterval).toLocaleString()}`));
  console.log("");
}

// Load private keys from file
function loadPrivateKeys() {
  try {
    const data = fs.readFileSync("privatekeys.txt", "utf8");
    privateKeys = data.split("\n")
      .map(key => key.trim())
      .filter(key => key.match(/^(0x)?[0-9a-fA-F]{64}$/));
    
    if (privateKeys.length === 0) {
      throw new Error("No valid private keys found in privatekeys.txt");
    }
  } catch (error) {
    log(`Failed to load private keys: ${error.message}`, "error");
    process.exit(1);
  }
}

// Load proxies from file
function loadProxies() {
  try {
    if (fs.existsSync("proxies.txt")) {
      const data = fs.readFileSync("proxies.txt", "utf8");
      proxies = data.split("\n")
        .map(proxy => proxy.trim())
        .filter(proxy => proxy)
        .map(p => p.startsWith('http') ? p : `http://${p}`);
    }
  } catch (error) {
    proxies = [];
  }
}

// Create proxy agent
function createAgent(proxyUrl) {
  if (!proxyUrl) return null;
  
  if (proxyUrl.startsWith("socks")) {
    return new SocksProxyAgent(proxyUrl);
  } else {
    return new HttpsProxyAgent(proxyUrl);
  }
}

// Get provider with proxy
function getProviderWithProxy(proxyUrl) {
  try {
    const agent = createAgent(proxyUrl);
    
    if (ethers.JsonRpcProvider) {
      const fetchOptions = agent ? { agent } : {};
      return new ethers.JsonRpcProvider(RPC_URL, { chainId: CHAIN_ID, name: "Helios" }, { fetchOptions });
    } else if (ethers.providers) {
      const connection = {
        url: RPC_URL,
        timeout: 30000
      };
      
      if (agent) {
        connection.agent = agent;
      }
      
      return new ethers.providers.JsonRpcProvider(connection, {
        chainId: CHAIN_ID,
        name: "Helios"
      });
    } else {
      throw new Error("Unsupported ethers version");
    }
  } catch (error) {
    if (ethers.providers) {
      return new ethers.providers.JsonRpcProvider(RPC_URL, {
        chainId: CHAIN_ID,
        name: "Helios"
      });
    } else {
      return new ethers.JsonRpcProvider(RPC_URL);
    }
  }
}

// Get next nonce
async function getNextNonce(provider, walletAddress) {
  try {
    const pendingNonce = await provider.getTransactionCount(walletAddress, "pending");
    const lastUsedNonce = nonceTracker[walletAddress] || pendingNonce - 1;
    const nextNonce = Math.max(pendingNonce, lastUsedNonce + 1);
    nonceTracker[walletAddress] = nextNonce;
    return nextNonce;
  } catch (error) {
    throw error;
  }
}

// Sleep function
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Helper functions for ethers version compatibility
function parseUnits(value, decimals) {
  if (ethers.parseUnits) {
    return ethers.parseUnits(value.toString(), decimals);
  } else {
    return ethers.utils.parseUnits(value.toString(), decimals);
  }
}

function formatUnits(value, decimals) {
  if (ethers.formatUnits) {
    return ethers.formatUnits(value, decimals);
  } else {
    return ethers.utils.formatUnits(value, decimals);
  }
}

function formatEther(value) {
  if (ethers.formatEther) {
    return ethers.formatEther(value);
  } else {
    return ethers.utils.formatEther(value);
  }
}

function toBeHex(value) {
  if (ethers.toBeHex) {
    return ethers.toBeHex(value);
  } else {
    return ethers.utils.hexlify(value);
  }
}

function zeroPadValue(value, length) {
  if (ethers.zeroPadValue) {
    return ethers.zeroPadValue(value, length);
  } else {
    return ethers.utils.hexZeroPad(value, length);
  }
}

function toUtf8Bytes(text) {
  if (ethers.toUtf8Bytes) {
    return ethers.toUtf8Bytes(text);
  } else {
    return ethers.utils.toUtf8Bytes(text);
  }
}

// Create axios instance with proxy
function createAxiosInstance(proxyUrl) {
  const instance = axios.create({
    timeout: 30000,
    headers: {
      'Content-Type': 'application/json',
      'Origin': 'https://testnet.helioschain.network',
      'Referer': 'https://testnet.helioschain.network/',
      'User-Agent': 'Mozilla/5.0'
    }
  });
  
  if (proxyUrl) {
    const agent = createAgent(proxyUrl);
    instance.defaults.httpsAgent = agent;
    instance.defaults.httpAgent = agent;
  }
  
  return instance;
}

// Sign message for faucet claim
async function signMessage(web3, wallet, pk) {
  const message = `Welcome to Helios! Please sign this message to verify your wallet ownership.\n\nWallet: ${wallet}`;
  return web3.eth.accounts.sign(message, pk).signature;
}

// Login to faucet
async function loginOnly(axios, wallet, signature) {
  try {
    const res = await axios.post(`${FAUCET_CONFIG.apiBaseUrl}/users/login`, {
      wallet,
      signature
    });
    return res.data.token;
  } catch (err) {
    if (err.response?.status === 404 || err.response?.status === 401) {
      log(`⚠️  Wallet ${wallet} not registered. Skipping faucet...`, "faucet");
      return null;
    } else {
      throw err;
    }
  }
}

// Claim faucet
async function claimFaucet(axios, token) {
  const res = await axios.post(`${FAUCET_CONFIG.apiBaseUrl}/faucet/request`, {
    token: 'HLS',
    chain: 'helios-testnet',
    amount: 1
  }, {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  return res.data;
}

// Claim faucet for wallet
async function claimFaucetForWallet(privateKey, proxyUrl) {
  try {
    const web3 = new Web3(new Web3.providers.HttpProvider(FAUCET_CONFIG.rpcUrl));
    const wallet = web3.eth.accounts.privateKeyToAccount(privateKey).address;
    
    const axiosInstance = createAxiosInstance(proxyUrl);
    const signature = await signMessage(web3, wallet, privateKey);
    const token = await loginOnly(axiosInstance, wallet, signature);

    if (!token) return false;

    const faucetResult = await claimFaucet(axiosInstance, token);
    log(`🎉 Faucet Success: ${faucetResult.message || '✅ Claimed'}`, "faucet");
    dailyStats.faucetClaims++;
    return true;
  } catch (err) {
    log(`❌ Faucet Error: ${err.response?.data?.message || err.message}`, "faucet");
    dailyStats.faucetClaimFails++;
    dailyStats.errors.push(`Faucet: ${err.response?.data?.message || err.message}`);
    return false;
  }
}

// Bridge function
async function bridge(wallet, amount, recipient) {
  try {
    const destChainId = 11155111;
    const chainIdHex = toBeHex(destChainId).slice(2).padStart(64, '0');
    const offset = "00000000000000000000000000000000000000000000000000000000000000a0";
    const token = TOKEN_ADDRESS.toLowerCase().slice(2).padStart(64, '0');
    
    const amountWei = parseUnits(amount, 18);
    const amountHex = zeroPadValue(toBeHex(amountWei), 32).slice(2);
    const gasParam = toBeHex(parseUnits("1", "gwei")).slice(2).padStart(64, '0');
    
    const recipientString = `0x${recipient.toLowerCase().slice(2)}`;
    const recipientLength = toBeHex(recipientString.length).slice(2).padStart(64, '0');
    const recipientPadded = Buffer.from(recipientString).toString('hex').padEnd(64, '0');
    
    const inputData = "0x7ae4a8ff" + 
      chainIdHex + 
      offset + 
      token + 
      amountHex + 
      gasParam + 
      recipientLength + 
      recipientPadded;

    // Check and approve allowance
    const tokenAbi = [
      "function allowance(address,address) view returns (uint256)",
      "function approve(address,uint256) returns (bool)"
    ];
    const tokenContract = new ethers.Contract(TOKEN_ADDRESS, tokenAbi, wallet);
    const allowance = await tokenContract.allowance(wallet.address, BRIDGE_ROUTER_ADDRESS);
    
    if (allowance.lt(amountWei)) {
      const approveTx = await tokenContract.approve(BRIDGE_ROUTER_ADDRESS, amountWei);
      await approveTx.wait();
    }

    const tx = {
      to: BRIDGE_ROUTER_ADDRESS,
      data: inputData,
      gasLimit: 1500000,
      chainId: CHAIN_ID,
      nonce: await getNextNonce(wallet.provider, wallet.address)
    };
    
    const sentTx = await wallet.sendTransaction(tx);
    log(`📤 Sent tx: ${getShortHash(sentTx.hash)}`, "info");
    
    const receipt = await sentTx.wait();
    if (receipt.status === 0) {
      throw new Error("Transaction reverted");
    }
    
    log(`✅ Confirmed`, "success");
    dailyStats.successfulBridges++;
    dailyStats.totalHlsBridged += parseFloat(amount);
  } catch (error) {
    dailyStats.failedBridges++;
    dailyStats.errors.push(`Bridge: ${error.message}`);
    throw error;
  }
}

// Stake function
async function stake(wallet, amount) {
  try {
    const fixedAddress = "0x007a1123a54cdd9ba35ad2012db086b9d8350a5f";
    const fixedBytes = "ahelios";
    
    let abiCoder;
    if (ethers.AbiCoder) {
      abiCoder = ethers.AbiCoder.defaultAbiCoder();
    } else {
      abiCoder = ethers.utils.defaultAbiCoder;
    }
    
    const encodedData = abiCoder.encode(
      ["address", "address", "uint256", "bytes"],
      [wallet.address, fixedAddress, parseUnits(amount, 18), toUtf8Bytes(fixedBytes)]
    );
    
    const inputData = "0xf5e56040" + encodedData.slice(2);
    
    const tx = {
      to: STAKE_ROUTER_ADDRESS,
      data: inputData,
      gasLimit: 1500000,
      chainId: CHAIN_ID,
      nonce: await getNextNonce(wallet.provider, wallet.address)
    };
    
    const sentTx = await wallet.sendTransaction(tx);
    log(`📤 Sent tx: ${getShortHash(sentTx.hash)}`, "info");
    
    const receipt = await sentTx.wait();
    if (receipt.status === 0) {
      throw new Error("Transaction reverted");
    }
    
    log(`✅ Confirmed`, "success");
    dailyStats.successfulStakes++;
    dailyStats.totalHlsStaked += parseFloat(amount);
  } catch (error) {
    dailyStats.failedStakes++;
    dailyStats.errors.push(`Stake: ${error.message}`);
    throw error;
  }
}

// Process single account (faucet claim + transactions)
async function processAccount(privateKey, proxyUrl, accountIndex, totalAccounts) {
  let accountSuccess = true;
  
  console.log(chalk.yellow(`--- Account ${accountIndex + 1} of ${totalAccounts} ---`));
  log(`🧭 Proxy: ${getShortProxy(proxyUrl)}`);
  
  try {
    const provider = getProviderWithProxy(proxyUrl);
    const wallet = new ethers.Wallet(privateKey, provider);
    
    log(`👛 Wallet: ${getShortAddress(wallet.address)}`);
    
    // Claim faucet first
    log(`🚰 Claiming faucet...`, "faucet");
    const faucetSuccess = await claimFaucetForWallet(privateKey, proxyUrl);
    
    if (faucetSuccess) {
      await sleep(autoConfig.delayBetweenActions); // Wait after faucet claim
    }

    // Get balances
    const tokenContract = new ethers.Contract(TOKEN_ADDRESS, ["function balanceOf(address) view returns (uint256)"], provider);
    const hlsBalance = await tokenContract.balanceOf(wallet.address);
    const nativeBalance = await provider.getBalance(wallet.address);
    
    log(`💵 HLS: ${formatUnits(hlsBalance, 18)} | token: ${formatEther(nativeBalance)}`);
    console.log("");

    // Bridge operations
    for (let bridgeCount = 1; bridgeCount <= autoConfig.bridgeRepetitions; bridgeCount++) {
      try {
        dailyStats.totalBridges++;
        const amountHLS = (Math.random() * (autoConfig.maxHlsBridge - autoConfig.minHlsBridge) + autoConfig.minHlsBridge).toFixed(4);
        const amountWei = parseUnits(amountHLS, 18);
        
        if (hlsBalance.lt(amountWei)) {
          dailyStats.failedBridges++;
          dailyStats.errors.push("Bridge: Insufficient HLS balance");
          continue;
        }
        
        log(`🔁 Bridge ${bridgeCount}/${autoConfig.bridgeRepetitions}`);
        log(`↳ Amount: ${amountHLS} HLS`);
        await bridge(wallet, amountHLS, wallet.address);
        
        if (bridgeCount < autoConfig.bridgeRepetitions) {
          await sleep(autoConfig.delayBetweenActions);
        }
      } catch (error) {
        accountSuccess = false;
        log(`❌ Bridge failed: ${error.message}`, "error");
        continue;
      }
    }

    // Wait before staking
    if (autoConfig.stakeRepetitions > 0) {
      await sleep(autoConfig.delayBetweenActions);
    }

    // Stake operations
    for (let stakeCount = 1; stakeCount <= autoConfig.stakeRepetitions; stakeCount++) {
      try {
        dailyStats.totalStakes++;
        const amountHLS = (Math.random() * (autoConfig.maxHlsStake - autoConfig.minHlsStake) + autoConfig.minHlsStake).toFixed(4);
        
        log(`🔐 Stake ${stakeCount}/${autoConfig.stakeRepetitions}`);
        log(`↳ Amount: ${amountHLS} HLS`);
        await stake(wallet, amountHLS);
        
        if (stakeCount < autoConfig.stakeRepetitions) {
          await sleep(autoConfig.delayBetweenActions);
        }
      } catch (error) {
        accountSuccess = false;
        log(`❌ Stake failed: ${error.message}`, "error");
        continue;
      }
    }

    return accountSuccess;
  } catch (error) {
    dailyStats.errors.push(`Account ${accountIndex + 1}: ${error.message}`);
    log(`❌ Account processing failed: ${error.message}`, "error");
    return false;
  }
}

// Main function to run daily activity
async function runDailyActivity() {
  dailyStats.startTime = Date.now();
  dailyStats.totalAccounts = privateKeys.length;
  
  console.log(chalk.cyan.bold(`
╔═══════════════════════════════════════╗
║         HELIOS TESTNET AUTO BOT       ║
║      with Auto Faucet Claim @ADFMIDN  ║
╚═══════════════════════════════════════╝
`));

  log(`Starting daily cycle...`);
  log(`Loaded ${privateKeys.length} wallets`);
  log(`Loaded ${proxies.length} proxies`);
  log(`Config: Bridge=${autoConfig.bridgeRepetitions}x | Stake=${autoConfig.stakeRepetitions}x | Faucet=Yes`);
  console.log("");

  for (let accountIndex = 0; accountIndex < privateKeys.length; accountIndex++) {
    const proxyUrl = proxies[accountIndex % proxies.length] || null;
    const accountSuccess = await processAccount(
      privateKeys[accountIndex], 
      proxyUrl, 
      accountIndex, 
      privateKeys.length
    );

    if (accountSuccess) {
      dailyStats.successfulAccounts++;
    } else {
      dailyStats.failedAccounts++;
    }

    // Wait before next account
    if (accountIndex < privateKeys.length - 1) {
      log(`⏳ Wait ${autoConfig.delayBetweenAccounts/1000}s for next wallet...`);
      console.log("");
      await sleep(autoConfig.delayBetweenAccounts);
    }
  }
  
  dailyStats.endTime = Date.now();
  displaySummary();
}

// Start infinite loop
async function startBot() {
  console.clear();
  
  let cycleCount = 1;
  
  while (true) {
    try {
      resetDailyStats();
      loadPrivateKeys();
      loadProxies();
      
      await runDailyActivity();
      
      cycleCount++;
      
      // Wait before next cycle
      log(`⏳ Waiting ${formatDuration(autoConfig.loopInterval)} for next cycle...`, "wait");
      await sleep(autoConfig.loopInterval);
      
    } catch (error) {
      log(`💥 Critical error in cycle #${cycleCount}: ${error.message}`, "error");
      log(`🔄 Restarting in 5 minutes...`, "wait");
      await sleep(5 * 60 * 1000); // Wait 5 minutes before retry
    }
  }
}

// Initialize and start
async function initialize() {
  try {
    await startBot();
  } catch (error) {
    log(`💥 Fatal error: ${error.message}`, "error");
    process.exit(1);
  }
}

// Handle process termination
process.on('SIGINT', () => {
  log("🛑 Bot stopped by user", "info");
  process.exit(0);
});

process.on('unhandledRejection', (reason, promise) => {
  // Silently handle rejections
});

process.on('uncaughtException', (error) => {
  log(`💥 Uncaught exception: ${error.message}`, "error");
  process.exit(1);
});

// Start the bot
initialize();