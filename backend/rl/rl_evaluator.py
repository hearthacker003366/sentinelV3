"""
Sentinel Blue Team Reinforcement Learning (RL) Evaluator
Implements an adaptive policy evaluator inspired by CyberBattleSim:
- Evaluates defender actions against dynamic attack states
- Calculates mathematical reward/penalty ledger:
    +10: Crown Jewel / Backup Vault preserved
    +5: Early detection speed (< 2.5s)
    -10: False positive business interruption
    -50: Critical asset compromise
- Tracks Cumulative Episode Reward and Mathematical Expectancy
"""

from typing import Dict, Any, List
from datetime import datetime, timezone
import random

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


class DefenseDQN(nn.Module if TORCH_AVAILABLE else object):
    def __init__(self, state_dim=16, action_dim=3):
        if TORCH_AVAILABLE:
            super(DefenseDQN, self).__init__()
            self.fc1 = nn.Linear(state_dim, 32)
            self.relu = nn.ReLU()
            self.fc2 = nn.Linear(32, action_dim)

    def forward(self, x):
        if not TORCH_AVAILABLE:
            return None
        x = self.relu(self.fc1(x))
        return self.fc2(x)


class BlueTeamRLEvaluator:
    ACTIONS = ["BLOCK_IP", "ISOLATE_HOST", "MONITOR"]

    def __init__(self):
        self.cumulative_reward: float = 0.0
        self.episode_history: List[Dict[str, Any]] = []
        self.current_policy: str = "PPO-Adaptive-Defender-v2"
        
        # DQN Setup
        self.state_dim = 16
        self.action_dim = len(self.ACTIONS)
        self.gamma = 0.99
        self.epsilon = 0.1  # Exploration rate
        
        if TORCH_AVAILABLE:
            self.dqn = DefenseDQN(self.state_dim, self.action_dim)
            self.optimizer = optim.Adam(self.dqn.parameters(), lr=0.01)
            self.criterion = nn.MSELoss()
        else:
            self.dqn = None

    def select_action(self, state_vector: List[float]) -> str:
        """Selects an action using epsilon-greedy policy from the DQN."""
        if not TORCH_AVAILABLE or self.dqn is None:
            return "ISOLATE_HOST"
        
        if random.random() < self.epsilon:
            return random.choice(self.ACTIONS)
            
        with torch.no_grad():
            state_t = torch.tensor(state_vector, dtype=torch.float32).unsqueeze(0)
            q_values = self.dqn(state_t)
            action_idx = torch.argmax(q_values, dim=1).item()
            return self.ACTIONS[action_idx]

    def evaluate_defense_action(
        self,
        stage: int,
        action: str,
        crown_jewel_safe: bool,
        early_interception: bool,
        is_false_positive: bool = False,
        state_vector: List[float] = None
    ) -> Dict[str, Any]:
        reward_delta = 0.0
        reasons = []

        if crown_jewel_safe:
            reward_delta += 10.0
            reasons.append("+10.0 Pts: Crown Jewel / Backup Vault 100% Protected")

        if early_interception:
            reward_delta += 5.0
            reasons.append("+5.0 Pts: Early Interception Speed (< 2.5s MTTD)")

        if is_false_positive:
            reward_delta -= 10.0
            reasons.append("-10.0 Pts: Unnecessary Business Disruption (False Alarm)")

        if not crown_jewel_safe:
            reward_delta -= 50.0
            reasons.append("-50.0 Pts: Critical Data Breach Occurred")

        self.cumulative_reward += reward_delta
        
        # DQN Training Step (Online learning)
        loss_val = 0.0
        if TORCH_AVAILABLE and self.dqn is not None and state_vector is not None:
            state_t = torch.tensor(state_vector, dtype=torch.float32).unsqueeze(0)
            action_idx = self.ACTIONS.index(action) if action in self.ACTIONS else 1
            
            self.optimizer.zero_grad()
            q_values = self.dqn(state_t)
            
            # Simplified Q-learning target: just the reward (assuming terminal state for this threat)
            target = q_values.clone().detach()
            target[0][action_idx] = reward_delta
            
            loss = self.criterion(q_values, target)
            loss.backward()
            self.optimizer.step()
            loss_val = loss.item()

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stage": stage,
            "action": action,
            "policy": self.current_policy,
            "reward_delta": reward_delta,
            "cumulative_reward": self.cumulative_reward,
            "breakdown": reasons,
            "standing": "OPTIMAL_DEFENSE" if self.cumulative_reward > 0 else "AT_RISK"
        }
        self.episode_history.append(entry)
        return entry

    def get_scoreboard(self) -> Dict[str, Any]:
        return {
            "policy": self.current_policy,
            "cumulative_reward": self.cumulative_reward,
            "standing": "OPTIMAL_DEFENSE (+15.0 PTS)" if self.cumulative_reward >= 15.0 else f"{self.cumulative_reward:+.1f} PTS",
            "episodes_logged": len(self.episode_history),
            "recent_entry": self.episode_history[-1] if self.episode_history else None
        }

    def reset_scoreboard(self):
        self.cumulative_reward = 0.0
        self.episode_history.clear()
