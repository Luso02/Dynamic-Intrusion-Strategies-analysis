#!/usr/bin/env python3
"""
Cyber attack simulator with dynamic strategies, parallel version.
Runs campaigns of simulations in parallel to speed up the analysis.
"""

import csv
import networkx as nx
import re
import ipaddress
from collections import defaultdict
import json
import os
import asyncio
import aiohttp
import nest_asyncio
import random
import numpy as np
import pandas as pd
from datetime import datetime
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing
from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
from openpyxl.utils import get_column_letter

# Assets and digital twin
class Asset:
    def __init__(self, name, **kwargs): 
        self.name = name
        self.attributes = kwargs
    
    def __repr__(self): 
        return f"{self.__class__.__name__}(name='{self.name}')"

class Host(Asset):
    def __init__(self, name, **kwargs): 
        super().__init__(name, **kwargs)

class Software(Asset):
    def __init__(self, name, **kwargs):
        super().__init__(name, **kwargs)
        self.base_name = kwargs.get('base_name')
        self.version = kwargs.get('version')

class VirtualMachine(Host): 
    pass

class CVEEnricher:
    def __init__(self, graph, api_key=None, cache_file='cve_cache.json'):
        self.graph = graph
        self.api_key = api_key
        self.cache_file = cache_file
        self.cve_cache = self._load_cache()

    def _load_cache(self):
        if os.path.exists(self.cache_file):
            with open(self.cache_file, 'r') as f: 
                return json.load(f)
        return {}

    def _save_cache(self):
        with open(self.cache_file, 'w') as f: 
            json.dump(self.cve_cache, f, indent=2)

    def _normalize_sw_name(self, name):
        return name.split('-')[0]

    async def _fetch_cve(self, session, sw_name, clean_version, original_key):
        if original_key in self.cve_cache:
            return original_key, self.cve_cache[original_key], '.'
        search_name = self._normalize_sw_name(sw_name)
        headers = {'apiKey': self.api_key} if self.api_key else {}
        query = f"keywordSearch={search_name} {clean_version}"
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}"
        try:
            async with session.get(url, headers=headers, timeout=40) as response:
                response.raise_for_status()
                data = await response.json()
                vulnerabilities = []
                if 'vulnerabilities' in data:
                    for item in data['vulnerabilities']:
                        cve = item['cve']
                        score = -1.0
                        if 'cvssMetricV31' in cve['metrics']: 
                            score = cve['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                        elif 'cvssMetricV2' in cve['metrics']: 
                            score = cve['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
                        vulnerabilities.append({'id': cve['id'], 'score': score})
                self.cve_cache[original_key] = vulnerabilities
                feedback_char = 'V' if vulnerabilities else '.'
                return original_key, vulnerabilities, feedback_char
        except Exception:
            self.cve_cache[original_key] = []
            return original_key, [], 'E'

    async def run_enrichment(self):
        unique_software = {
            f"{data.get('base_name', '').lower()}|{data.get('version', '')}": 
            (data.get('base_name'), re.match(r'[\d\.:]+', data.get('version', '')).group(0) 
             if re.match(r'[\d\.:]+', data.get('version', '')) else data.get('version', '')) 
            for _, data in self.graph.nodes(data=True) 
            if data.get('type') == 'Software' and data.get('base_name') and data.get('version')
        }
        items_to_fetch = [
            (key, sw_name, clean_version) 
            for key, (sw_name, clean_version) in unique_software.items() 
            if key not in self.cve_cache
        ]
        if items_to_fetch:
            async with aiohttp.ClientSession() as session:
                results = await asyncio.gather(*[
                    self._fetch_cve(session, sw_name, clean_version, key) 
                    for key, sw_name, clean_version in items_to_fetch
                ])
        for node_name, data in self.graph.nodes(data=True):
            if data.get('type') == 'Software':
                key = f"{data.get('base_name', '').lower()}|{data.get('version', '')}"
                if (vulnerabilities := self.cve_cache.get(key)):
                    self.graph.nodes[node_name]['vulnerabilities'] = vulnerabilities
                    self.graph.nodes[node_name]['max_cvss'] = max(
                        [v['score'] for v in vulnerabilities if v['score'] >= 0] or [0.0]
                    )
        self._save_cache()
        print(f"CVE: {len(unique_software)} software, {len(items_to_fetch)} fetch eseguiti.")


class DigitalTwin:
    def __init__(self):
        self.graph = nx.DiGraph()
        self.assets = {}
        self.discovered_subnets = []
    
    def _parse_multiline_data(self, data: str):
        return [item.strip() for item in data.split('<br>') if item.strip()] if isinstance(data, str) else []
    
    def _parse_software_data(self, data: str):
        return [
            {'name': parts[0].strip(), 'version': parts[1].strip()} 
            for line in self._parse_multiline_data(data) 
            if len(parts := line.rsplit(' - ', 1)) == 2
        ]
    
    def _discover_subnets_from_rows(self, all_rows):
        subnet_prefixes = set()
        for row in all_rows:
            for ip_str in self._parse_multiline_data(row.get('Networking - IP', '')):
                try:
                    ip_addr = ipaddress.ip_address(ip_str)
                    if not (ip_addr.is_loopback or ip_addr.version == 6 or not ip_addr.is_private):
                        subnet_prefixes.add('.'.join(ip_str.split('.')[:3]))
                except ValueError: 
                    continue
        self.discovered_subnets = [
            ipaddress.ip_network(f"{prefix}.0/24") 
            for prefix in sorted(list(subnet_prefixes))
        ]
        print(f"Sottoreti scoperte: {len(self.discovered_subnets)}")
    
    def _get_subnet_for_ips(self, ips):
        for ip_str in ips:
            try:
                if (subnet := next((str(s) for s in self.discovered_subnets if ipaddress.ip_address(ip_str) in s), None)): 
                    return subnet
            except ValueError: 
                continue
        return 'Unknown/External'
    
    def _add_or_get_asset(self, name, asset_class, **kwargs):
        if name not in self.assets:
            self.assets[name] = asset_class(name, **kwargs)
            self.graph.add_node(name, type=asset_class.__name__, **kwargs)
        elif kwargs: 
            nx.set_node_attributes(self.graph, {name: kwargs})
        return self.assets[name]
    
    def load_from_csv(self, file_path, delimiter=';'):
        with open(file_path, mode='r', encoding='utf-8-sig') as infile:
            next(infile)
            all_rows = list(csv.DictReader(infile, delimiter=delimiter))
        self._discover_subnets_from_rows(all_rows)
        for row in all_rows:
            if not (host_name := row.get('Name')): 
                continue
            ips = self._parse_multiline_data(row.get('Networking - IP', ''))
            subnet = self._get_subnet_for_ips(ips)
            host_attributes = {
                'os': row.get('Operating System - Name'), 
                'asset_type': row.get('Type'), 
                'ips': ips, 
                'subnet': subnet
            }
            self._add_or_get_asset(
                host_name, 
                VirtualMachine if host_attributes['asset_type'] == 'VM' else Host, 
                **host_attributes
            )
            for vm_name in self._parse_multiline_data(row.get('Virtual machines - Name', '')):
                self._add_or_get_asset(vm_name, VirtualMachine, os=host_attributes['os'], subnet=subnet)
                self.graph.add_edge(host_name, vm_name, relationship='HOSTS')
            for sw in self._parse_software_data(row.get('Software - Name', '')):
                sw_unique_name = f"{sw['name']} ({sw['version']})"
                self._add_or_get_asset(sw_unique_name, Software, base_name=sw['name'], version=sw['version'])
                self.graph.add_edge(host_name, sw_unique_name, relationship='INSTALLS')
        print(f"Grafo costruito: {self.graph.number_of_nodes()} nodi, {self.graph.number_of_edges()} archi.")
    
    def get_graph(self): 
        return self.graph


# State of a single intrusion
class AttackerState:
    def __init__(self, initial_host):
        self.compromised_hosts = {initial_host: {'priv_level': 'user'}}
        self.credentials = set()
        self.current_time_hours = 0.0
        self.path = ['Attacker', initial_host]
        self.detected = False
        self.goal_achieved = False
        self.noise_level = 0.0


# Attack strategies
class AttackStrategy:
    def __init__(self, simulator): 
        self.sim = simulator
    
    def choose_next_action(self, state, current_host): 
        raise NotImplementedError
    
    def choose_target(self, state, current_host, available_targets): 
        raise NotImplementedError
    
    def __str__(self): 
        return self.__class__.__name__


class GreedyValueStrategy(AttackStrategy):
    def choose_next_action(self, state, host):
        if state.compromised_hosts[host]['priv_level'] == 'user': 
            return 'PRIV_ESC'
        if 'domain_admin' not in state.credentials and self.sim.dt_graph.nodes[host].get('value', 0) >= 1000: 
            return 'DUMP_CREDS'
        if 'local_admin' not in state.credentials: 
            return 'DUMP_CREDS'
        return 'LATERAL_MOVE'
    
    def choose_target(self, state, current_host, targets):
        if not targets: 
            return None
        return max(targets, key=lambda t: self.sim.dt_graph.nodes[t].get('value', 1))


class StealthStrategy(AttackStrategy):
    def __init__(self, simulator, noise_threshold=10.0):
        super().__init__(simulator)
        self.noise_threshold = noise_threshold
    
    def choose_next_action(self, state, host):
        if state.noise_level > self.noise_threshold: 
            return 'WAIT'
        priv_level = state.compromised_hosts[host]['priv_level']
        if 'domain_admin' in state.credentials or 'local_admin' in state.credentials: 
            return 'LATERAL_MOVE'
        if priv_level == 'user': 
            return 'PRIV_ESC'
        if priv_level == 'admin': 
            return 'DUMP_CREDS'
        return 'LATERAL_MOVE'
    
    def choose_target(self, state, current_host, targets):
        if not targets: 
            return None
        return min(targets, key=lambda t: self.sim.dt_graph.nodes[t].get('value', 1))


class NoisyGoalOrientedStrategy(AttackStrategy):
    """A noisy, goal-driven attacker."""
    def __init__(self, simulator, noise_multiplier=2.5):
        super().__init__(simulator)
        self.noise_multiplier = noise_multiplier

    def choose_next_action(self, state, host):
        if state.compromised_hosts[host]['priv_level'] == 'user' and random.random() < 0.9:
             return 'PRIV_ESC'
        if self.sim.dt_graph.nodes[host].get('value', 0) >= 500:
            return 'DUMP_CREDS'
        return random.choices(
            ['LATERAL_MOVE', 'DUMP_CREDS', 'PRIV_ESC'], 
            weights=[0.7, 0.2, 0.1], k=1
        )[0]

    def choose_target(self, state, current_host, targets):
        if not targets:
            return None
        weights = [self.sim.dt_graph.nodes[t].get('value', 1) for t in targets]
        return random.choices(targets, weights=weights, k=1)[0]


class MaxProbabilityStrategy(AttackStrategy):
    def choose_next_action(self, state, host):
        if state.compromised_hosts[host]['priv_level'] == 'user': 
            return 'PRIV_ESC'
        if 'domain_admin' not in state.credentials and self.sim.dt_graph.nodes[host].get('value', 0) >= 1000: 
            return 'DUMP_CREDS'
        if 'local_admin' not in state.credentials: 
            return 'DUMP_CREDS'
        return 'LATERAL_MOVE'
    
    def _get_max_cvss_for_host(self, target_host):
        vulns = [
            self.sim.dt_graph.nodes[s].get('max_cvss', 0.0) 
            for s in self.sim.dt_graph.successors(target_host) 
            if self.sim.dt_graph.nodes[s].get('type') == 'Software' and self.sim.dt_graph.nodes[s].get('vulnerabilities')
        ]
        return max(vulns) if vulns else 0.0
    
    def choose_target(self, state, current_host, targets):
        if not targets: 
            return None
        return max(targets, key=lambda t: self._get_max_cvss_for_host(t))


class SwitchOnStallStrategy(AttackStrategy):
    
    
    def __init__(self, simulator, strategy_a_name='MaxProbabilityStrategy', 
                 strategy_b_name='NoisyGoalOrientedStrategy', stall_threshold=4, h=None):
        super().__init__(simulator)
        
        # Instantiate the component strategies
        self.strat_greedy = GreedyValueStrategy(simulator)
        self.strat_max_prob = MaxProbabilityStrategy(simulator)
        self.strat_stealth = StealthStrategy(simulator)
        self.strat_noisy = NoisyGoalOrientedStrategy(simulator)
        
        # Pick strategies A and B by name
        self.strategy_a = self._resolve_strategy(strategy_a_name)
        self.strategy_b = self._resolve_strategy(strategy_b_name)
        
        # Config
        self.stall_threshold = stall_threshold
        self.duration_b = h
        
        # Names for logging
        self.strategy_a_name = strategy_a_name if isinstance(strategy_a_name, str) else strategy_a_name.__name__
        self.strategy_b_name = strategy_b_name if isinstance(strategy_b_name, str) else strategy_b_name.__name__
        
    def _resolve_strategy(self, strategy_name):
        
        # Name to instance
        strategy_instances = {
            'GreedyValueStrategy': self.strat_greedy,
            'MaxProbabilityStrategy': self.strat_max_prob,
            'StealthStrategy': self.strat_stealth,
            'NoisyGoalOrientedStrategy': self.strat_noisy,
        }
        
        if isinstance(strategy_name, type):
            strategy_name = strategy_name.__name__
        
        if strategy_name in strategy_instances:
            return strategy_instances[strategy_name]
        
        raise ValueError(f"Strategia '{strategy_name}' non riconosciuta. "
                        f"Opzioni valide: {list(strategy_instances.keys())}")
    
    def _initialize_state(self, state):
        
        # Set up the strategy-tracking state
        state._last_progress_score = -1  # Progress score: compromised hosts + credentials
        state._stall_count = 0
        state._actions_in_b = 0                     # Actions taken in B
        state._using_strategy_b = False
        state._returned_to_a = False                # True once we are back on A after h steps
        state._active_strategy = self.strategy_a    # Currently active strategy
        
    def _get_progress_score(self, state):
        
        # Progress = compromised hosts + credentials
        return len(state.compromised_hosts) + len(state.credentials)
    
    def _update_strategy_state(self, state):
        
        # Already back on A for good
        if state._returned_to_a:
            state._active_strategy = self.strategy_a
            return
        
        # Back to A after h actions in B
        if state._using_strategy_b and self.duration_b is not None:
            if state._actions_in_b >= self.duration_b:
                state._using_strategy_b = False
                state._returned_to_a = True
                state._active_strategy = self.strategy_a
                return
        
        # Current progress
        current_score = self._get_progress_score(state)
        
        # Switch to B if stalled
        if not state._using_strategy_b and not state._returned_to_a:
            if current_score > state._last_progress_score:
                # Progress made: reset the stall counter
                state._last_progress_score = current_score
                state._stall_count = 0
            else:
                # No progress: count a stall
                state._stall_count += 1
            
            # Switch to B at the threshold
            if state._stall_count >= self.stall_threshold:
                state._using_strategy_b = True
                state._actions_in_b = 0
                state._active_strategy = self.strategy_b
                return
        
        # In B: count the action
        if state._using_strategy_b and not state._returned_to_a:

            if current_score > state._last_progress_score:
                state._actions_in_b += 1
                state._last_progress_score = current_score
            else:
                state._actions_in_b += 1
        
        # Set the active strategy from the current state
        state._active_strategy = self.strategy_b if state._using_strategy_b else self.strategy_a
    
    def choose_next_action(self, state, host):

        # First call: set up the state
        if not hasattr(state, '_active_strategy'):
            self._initialize_state(state)
        
        # Update the strategy state (once per step)
        self._update_strategy_state(state)
        
        return state._active_strategy.choose_next_action(state, host)
    
    def choose_target(self, state, current_host, targets):
        return state._active_strategy.choose_target(state, current_host, targets)
    
    def __str__(self):
        base_str = f"SwitchAll_{self.strategy_a_name[:3]}_{self.strategy_b_name[:3]}_K{self.stall_threshold}"
        if self.duration_b is not None:
            return f"{base_str}_H{self.duration_b}"
        return base_str




def create_switch_strategy(strategy_a_name, strategy_b_name, stall_threshold=4, h=None):
  
    class ConfiguredSwitchStrategy(SwitchOnStallStrategy):
        def __init__(self, simulator):
            super().__init__(simulator, strategy_a_name, strategy_b_name, stall_threshold, h)
    
    # Readable class name
    if h is not None:
        ConfiguredSwitchStrategy.__name__ = f"Switch_{strategy_a_name[:3]}_{strategy_b_name[:3]}_K{stall_threshold}_H{h}"
    else:
        ConfiguredSwitchStrategy.__name__ = f"Switch_{strategy_a_name[:3]}_{strategy_b_name[:3]}_K{stall_threshold}"
    
    return ConfiguredSwitchStrategy

class StochasticMaxProbStrategy(AttackStrategy):
    """
    Stochastic hybrid: MaxProbability is the base, but at each step it
    deviates with probability p, making the attack less predictable and
    lowering the detection rate.
    """
    def __init__(self, simulator, perturbation_prob=0.01, deviation_mode='stealth'):
        super().__init__(simulator)
        self.perturbation_prob = perturbation_prob  # p: e.g. 0.01, 0.03, 0.05
        self.deviation_mode = deviation_mode  # 'stealth', 'random', 'mixed'
        self.maxprob_strategy = MaxProbabilityStrategy(simulator)
        self.stealth_strategy = StealthStrategy(simulator, noise_threshold=10.0)
        self._deviations_count = 0
        self._total_actions = 0
        
    def choose_next_action(self, state, host):
        self._total_actions += 1
        # With probability p, deviate from MaxProb
        if random.random() < self.perturbation_prob:
            self._deviations_count += 1
            if self.deviation_mode == 'stealth':
                # Take a Stealth action
                return self.stealth_strategy.choose_next_action(state, host)
            elif self.deviation_mode == 'random':
                # Any random action
                return random.choice(['PRIV_ESC', 'DUMP_CREDS', 'LATERAL_MOVE', 'WAIT'])
        
        # Otherwise follow MaxProb
        return self.maxprob_strategy.choose_next_action(state, host)
    
    def _get_max_cvss_for_host(self, target_host):
            """
            Max CVSS across all software installed on a host.
            """
            vulns = [
                self.sim.dt_graph.nodes[s].get('max_cvss', 0.0) 
                for s in self.sim.dt_graph.successors(target_host) 
                if self.sim.dt_graph.nodes[s].get('type') == 'Software' 
                and self.sim.dt_graph.nodes[s].get('vulnerabilities')
            ]
            return max(vulns) if vulns else 0.0
    
    
    def choose_target(self, state, current_host, targets):
        all_targets = [
            n for n, d in self.sim.dt_graph.nodes(data = True)
            if d.get('type') in ['Host', 'VirtualMachine'] and n not in state.compromised_hosts
        ]
        if not all_targets: return None

        """if random.random() < self.cross_prob:
            return random.choice(all_targets)
        return self.maxprob.choose_target(state, current_host, targets)
    """
        return max(all_targets, key = lambda t: self._get_max_cvss_for_host(t))

def create_stochastic_variant(p, mode='stealth'):
    class VariantStrategy(StochasticMaxProbStrategy):
        def __init__(self, sim):
            super().__init__(sim, perturbation_prob=p, deviation_mode=mode)
    return VariantStrategy
 


# Simulation engine
class AttackSimulator:
    TIME_MODEL = {
        'SCAN': (1.0, 1.0), 
        'EXPLOIT': (0.1, 2), 
        'PRIV_ESC': (0.2, 3), 
        'DUMP_CREDS': (0.1, 0.5), 
        'LOGIN': (0.01, 0.1)
    }
    NOISE_MODEL = {
        'SCAN': 1.5, 
        'EXPLOIT': 2.0, 
        'PRIV_ESC': 1.0, 
        'DUMP_CREDS': 1.2, 
        'LOGIN': 0.2
    }

    def __init__(self, dt_graph, strategy_class, skill=0.8, detection_rate=0.05):
        self.dt_graph = dt_graph
        self.strategy = strategy_class(self)
        self.skill = skill
        self.detection_rate = detection_rate
        self.attack_graph = nx.DiGraph()
        self._assign_asset_values()
        self.stats = self._reset_stats()

    def _reset_stats(self):
        return {
            'total': 0, 
            'succeeded': 0, 
            'failed': 0, 
            'detected': 0,
            'actions': defaultdict(int), 
            'exploited_cves': defaultdict(int),
            'compromised_nodes': defaultdict(int),
            'successful_path_details': defaultdict(list),
            'detected_paths': []
        }

    def _assign_asset_values(self):
        value_map = {'dc': 1000, 'db': 500, 'sql': 500, 'fileserver': 200, 'admin': 100}
        for node, data in self.dt_graph.nodes(data=True):
            if data.get('type') in ['Host', 'VirtualMachine']:
                self.dt_graph.nodes[node]['value'] = max(
                    [1] + [v for keyword, v in value_map.items() if keyword in node.lower()]
                )
    
    def _select_entry_point(self):
        web_keywords = ['apache', 'nginx', 'iis', 'httpd', 'tomcat']
        candidates = [
            (host, 1 + data.get('value', 1) + 10 * any(
                any(key in sw_name for key in web_keywords) 
                for sw in self.dt_graph.successors(host) 
                if (sw_name := self.dt_graph.nodes[sw].get('base_name', '').lower())
            )) 
            for host, data in self.dt_graph.nodes(data=True) 
            if data.get('type') in ['Host', 'VirtualMachine'] and data.get('subnet') == 'Unknown/External'
        ]
        if not candidates: 
            return random.choice([
                n for n, d in self.dt_graph.nodes(data=True) 
                if d.get('type') in ['Host', 'VirtualMachine']
            ])
        return random.choices(*zip(*candidates), k=1)[0]
    
    def _get_noise_for_action(self, action):
        base_noise = self.NOISE_MODEL.get(action, 1.0)
        multiplier = getattr(self.strategy, 'noise_multiplier', 1.0)
        return base_noise * multiplier

    def _run_single_intrusion(self):
        self.stats['total'] += 1
        entry_host = self._select_entry_point()
        sw, vuln = self._attempt_exploit_cve(entry_host)
        if not sw: 
            self.stats['failed'] += 1
            return
        
        state = AttackerState(entry_host)
        state.current_time_hours += self._get_time('EXPLOIT')
        state.noise_level += self._get_noise_for_action('EXPLOIT')
        self._log_action('Initial Compromise Success', entry_host, (vuln['id'], entry_host))
        
        while not state.detected and not state.goal_achieved and state.current_time_hours < 120:
            host = state.path[-1]
            if self.dt_graph.nodes[host].get('value', 0) >= 1000: 
                state.goal_achieved = True
                continue
            action = self.strategy.choose_next_action(state, host)
            if action == 'PRIV_ESC': 
                self._attempt_privesc(state, host)
            elif action == 'DUMP_CREDS': 
                self._attempt_credential_dump(state, host)
            elif action == 'LATERAL_MOVE': 
                self._attempt_lateral_move(state, host)
            elif action == 'WAIT': 
                state.current_time_hours += 12
                state.noise_level *= 0.75
        
        if state.goal_achieved or len(state.compromised_hosts) > 1:
            self.stats['succeeded'] += 1
            path_tuple = tuple(state.path)
            self.stats['successful_path_details'][path_tuple].append({
                'time': state.current_time_hours,
                'steps': len(state.path)
            })
        elif state.detected:
            self.stats['detected'] += 1
            self.stats['detected_paths'].append(tuple(state.path))
        else:
            self.stats['failed'] += 1

    def _attempt_lateral_move(self, state, current_host):
        state.current_time_hours += self._get_time('SCAN')
        state.noise_level += self._get_noise_for_action('SCAN')
        if self._check_detection(state, 'SCAN'): 
            return
        subnet = self.dt_graph.nodes[current_host].get('subnet')
        targets = [
            n for n, d in self.dt_graph.nodes(data=True) 
            if d.get('type') in ['Host', 'VirtualMachine'] 
            and d.get('subnet') == subnet 
            and n not in state.compromised_hosts
        ]
        target_host = self.strategy.choose_target(state, current_host, targets)
        if not target_host: 
            self._log_action('Lateral Move Failure (No Targets)')
            return
        
        moved, move_method, sw, vuln = False, "", None, None
        if 'domain_admin' in state.credentials and random.random() < 0.95: 
            moved, move_method = True, "Lateral Move (DA)"
        elif 'local_admin' in state.credentials and random.random() < 0.6: 
            moved, move_method = True, "Lateral Move (LA)"
        
        if moved: 
            state.current_time_hours += self._get_time('LOGIN')
            state.noise_level += self._get_noise_for_action('LOGIN')
        else:
            state.current_time_hours += self._get_time('EXPLOIT')
            state.noise_level += self._get_noise_for_action('EXPLOIT')
            if self._check_detection(state, 'EXPLOIT'): 
                return
            sw, vuln = self._attempt_exploit_cve(target_host)
            if sw: 
                moved, move_method = True, "Lateral Move (Exploit)"
                self._log_action(move_method, target_host, (vuln['id'], target_host))
        
        if moved:
            state.compromised_hosts[target_host] = {'priv_level': 'user'}
            state.path.append(target_host)
            self._log_action(move_method, host=target_host)
        else: 
            self._log_action('Lateral Move Failure')

    def _get_time(self, action): 
        return random.uniform(*self.TIME_MODEL[action]) / self.skill
    
    def _check_detection(self, state, action):
        if random.random() < self.detection_rate * self._get_noise_for_action(action):
            state.detected = True
            return True
        return False
    
    def _attempt_exploit_cve(self, target_host):
        vulns = [
            (s, max(self.dt_graph.nodes[s].get('vulnerabilities', []), key=lambda v: v['score'])) 
            for s in self.dt_graph.successors(target_host) 
            if self.dt_graph.nodes[s].get('type') == 'Software' and self.dt_graph.nodes[s].get('vulnerabilities')
        ]
        if not vulns: 
            return None, None
        sw_node, best_vuln = max(vulns, key=lambda item: item[1]['score'])
        if random.random() < (best_vuln['score'] / 10.0) * self.skill: 
            return sw_node, best_vuln
        return None, None
    
    def _attempt_privesc(self, state, host):
        state.current_time_hours += self._get_time('PRIV_ESC')
        state.noise_level += self._get_noise_for_action('PRIV_ESC')
        if self._check_detection(state, 'PRIV_ESC'): 
            return
        if random.random() < 0.7 * self.skill:
            state.compromised_hosts[host]['priv_level'] = 'admin'
            self._log_action('PrivEsc Success')
    
    def _attempt_credential_dump(self, state, host):
        if state.compromised_hosts[host]['priv_level'] != 'admin': 
            return
        state.current_time_hours += self._get_time('DUMP_CREDS')
        state.noise_level += self._get_noise_for_action('DUMP_CREDS')
        if self._check_detection(state, 'DUMP_CREDS'): 
            return
        if random.random() < 0.8 * self.skill:
            new_cred = 'domain_admin' if self.dt_graph.nodes[host].get('value', 0) >= 1000 else 'local_admin'
            state.credentials.add(new_cred)
            self._log_action(f'Credential Dump Success ({new_cred})')

    def _log_action(self, action_name, host=None, cve_tuple=None):
        self.stats['actions'][action_name] += 1
        if host: 
            self.stats['compromised_nodes'][host] += 1
        if cve_tuple: 
            self.stats['exploited_cves'][cve_tuple] += 1
    
    def run_simulations(self, num_simulations=100):
        self.attack_graph = nx.DiGraph()
        self.attack_graph.add_node("Attacker", type='Attacker')
        self.stats = self._reset_stats()
        for i in range(num_simulations):
            self._run_single_intrusion()
        return self.stats, self.attack_graph



BASE_COLORS = ['FFE6E6', 'E6F3FF', 'E6FFE6', 'FFF5E6', 'F0E6FF', 'FFFFE6', 'FFE6F0', 'E6FFFF']

METRIC_COLUMNS = ['Successo (%)', 'Fallimento (%)', 'Rilevamento (%)',
                  'Passi Medi', 'Tempo Medio (h)', 'Simulazioni Totali']


def save_results(all_results, group_key, output_file):
    # Group results, compute means and save a formatted Excel file.

    # Group runs and add MEDIA (mean) rows
    groups = {}
    for r in all_results:
        groups.setdefault(r[group_key], []).append(r)

    sorted_keys = sorted(groups,
                         key=lambda x: (-1, '') if x in ('None', None)
                         else (0, x))

    rows = []
    for val in sorted_keys:
        group = groups[val]
        rows.extend(group)
        mean_row = {group_key: f'MEDIA {group_key}={val}', 'Campagna': ''}
        for col in METRIC_COLUMNS:
            avg = np.mean([r[col] for r in group])
            mean_row[col] = int(round(avg)) if col == 'Simulazioni Totali' else round(avg, 2)
        rows.append(mean_row)

    df = pd.DataFrame(rows)

    # Aggregate stats (mean + 95% CI)
    df_raw = pd.DataFrame(all_results)
    grouped = df_raw.groupby(group_key)
    
    agg_mean = {}
    for c in METRIC_COLUMNS:
        if c != 'Simulazioni Totali':
            agg_mean[c] = 'mean'
        else:
            agg_mean[c] = 'mean'
    df_means = grouped.agg(agg_mean).round(2)
    
    # 95% CI = 1.96 * std / sqrt(n)
    ci_cols = {}
    for c in METRIC_COLUMNS:
        if c != 'Simulazioni Totali':
            std_vals = grouped[c].std()
            count_vals = grouped[c].count()
            ci_vals = (1.96 * std_vals / np.sqrt(count_vals)).round(2)
            ci_cols[f'{c} CI 95%'] = ci_vals
    df_ci = pd.DataFrame(ci_cols)
    
    # Interleave mean and CI columns: mean, CI, mean, CI, ...
    summary_cols = []
    for c in METRIC_COLUMNS:
        summary_cols.append(df_means[c])
        if c != 'Simulazioni Totali':
            summary_cols.append(df_ci[f'{c} CI 95%'])
    df_summary = pd.concat(summary_cols, axis=1)

    # Color palette per group
    unique_vals = list(dict.fromkeys(
        r[group_key] for r in rows
        if not (isinstance(r[group_key], str) and r[group_key].startswith('MEDIA'))
    ))
    palette = {v: BASE_COLORS[i % len(BASE_COLORS)] for i, v in enumerate(unique_vals)}

    # Styles
    header_fill = PatternFill(start_color='4472C4', end_color='4472C4', fill_type='solid')
    header_font = Font(bold=True, color='FFFFFF', size=11)
    mean_fill = PatternFill(start_color='808080', end_color='808080', fill_type='solid')
    mean_font = Font(bold=True, color='FFFFFF', size=11)
    center = Alignment(horizontal='center', vertical='center')
    border = Border(*(Side(style='thin'),) * 4)

    # Write the Excel file
    with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Dati Completi', index=False)
        df_summary.to_excel(writer, sheet_name=f'Statistiche per {group_key}')
        ws = writer.sheets['Dati Completi']

        # Header
        for c in range(1, len(df.columns) + 1):
            cell = ws.cell(row=1, column=c)
            cell.fill, cell.font, cell.alignment, cell.border = header_fill, header_font, center, border

        # Data rows
        for r_idx, row_data in enumerate(rows, 2):
            val = row_data[group_key]
            is_mean = isinstance(val, str) and val.startswith('MEDIA')
            for c in range(1, len(df.columns) + 1):
                cell = ws.cell(row=r_idx, column=c)
                cell.border, cell.alignment = border, center
                if is_mean:
                    cell.fill, cell.font = mean_fill, mean_font
                else:
                    color = palette.get(val, 'FFFFFF')
                    cell.fill = PatternFill(start_color=color, end_color=color, fill_type='solid')

        # Column widths
        for c, col_name in enumerate(df.columns, 1):
            max_len = len(str(col_name))
            for row_data in rows:
                val = row_data.get(col_name, '')
                max_len = max(max_len, len(str(val)))
            ws.column_dimensions[get_column_letter(c)].width = max_len + 4

        # Format the stats sheet
        ws2 = writer.sheets[f'Statistiche per {group_key}']
        n_cols_s = ws2.max_column
        n_rows_s = ws2.max_row

        # Header (row 1)
        for c in range(1, n_cols_s + 1):
            cell = ws2.cell(row=1, column=c)
            cell.fill, cell.font, cell.alignment, cell.border = header_fill, header_font, center, border

        # Data rows, no color
        for r_idx in range(2, n_rows_s + 1):
            for c in range(1, n_cols_s + 1):
                cell = ws2.cell(row=r_idx, column=c)
                cell.border, cell.alignment = border, center

        # Column widths
        for col in ws2.columns:
            max_len = 0
            col_letter = get_column_letter(col[0].column)
            for cell in col:
                if cell.value is not None:
                    max_len = max(max_len, len(str(cell.value)))
            ws2.column_dimensions[col_letter].width = max_len + 4

    print(f"Salvato: {output_file}")


# Strategy name to class
STRATEGY_MAP = {
    'MaxProbabilityStrategy': MaxProbabilityStrategy,
    'NoisyGoalOrientedStrategy': NoisyGoalOrientedStrategy,
    'GreedyValueStrategy': GreedyValueStrategy,
    'StealthStrategy': StealthStrategy
}


# Runs a single campaign
def run_single_campaign(args):

    params = args  # dict

    mode = params['mode']
    campaign_num = params['campaign_num']
    dt_graph = nx.node_link_graph(params['dt_graph_data'])
    check_interval = params['check_interval']
    stabilization_threshold = params['stabilization_threshold']
    max_simulations = params['max_simulations']
    skill = params['skill']
    detection_rate = params['detection_rate']

    # Build the strategy for this mode
    if mode == 'base':
        strategy_name = params['strategy_name']
        strategy_class = STRATEGY_MAP.get(strategy_name)
        if strategy_class is None:
            raise ValueError(f"Strategia '{strategy_name}' non riconosciuta")
    elif mode == 'p':
        strategy_class = create_stochastic_variant(
            p=params['p_value'],
            mode=params['deviation_mode']
        )
    else:
        strategy_class = create_switch_strategy(
            strategy_a_name=params['strategy_A_name'],
            strategy_b_name=params['strategy_B_name'],
            stall_threshold=params['k_value'],
            h=params['h_value']
        )

    # Build the simulator
    simulator = AttackSimulator(
        dt_graph,
        strategy_class,
        skill=skill,
        detection_rate=detection_rate
    )

    # Path discovery, until the path count stabilizes
    total_sims_run = 0
    sims_since_last_path = 0
    last_path_count = 0
    aggregated_stats = simulator._reset_stats()

    while total_sims_run < max_simulations:
        batch_stats, _ = simulator.run_simulations(num_simulations=check_interval)
        total_sims_run += check_interval

        for key, value in batch_stats.items():
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    aggregated_stats[key][sub_key] += sub_value
            elif isinstance(value, list):
                aggregated_stats[key].extend(value)
            else:
                aggregated_stats[key] += value

        current_path_count = len(aggregated_stats['successful_path_details'])
        if current_path_count > last_path_count:
            sims_since_last_path = 0
            last_path_count = current_path_count
        else:
            sims_since_last_path += check_interval

        if sims_since_last_path >= stabilization_threshold:
            break

    simulator.stats = aggregated_stats

    # Extract metrics
    total_simulations = aggregated_stats['total']
    success_count = aggregated_stats['succeeded']
    detected_count = aggregated_stats['detected']
    failed_count = aggregated_stats['failed']

    success_rate = (success_count / total_simulations * 100) if total_simulations > 0 else 0
    detection_rate_pct = (detected_count / total_simulations * 100) if total_simulations > 0 else 0
    failure_rate = (failed_count / total_simulations * 100) if total_simulations > 0 else 0

    if success_count > 0:
        all_times = [
            run['time']
            for path_runs in aggregated_stats['successful_path_details'].values()
            for run in path_runs
        ]
        all_steps = [
            run['steps']
            for path_runs in aggregated_stats['successful_path_details'].values()
            for run in path_runs
        ]
        avg_time = np.mean(all_times)
        avg_steps = np.mean(all_steps)
    else:
        avg_time = 0
        avg_steps = 0

    # Build the result, group key right after Campagna
    if mode == 'k':
        group_entry = {'k': params['k_value']}
    elif mode == 'h':
        h = params['h_value']
        group_entry = {'h': h if h is not None else 'None'}
    elif mode == 'p':
        group_entry = {'p (%)': params['p_value'] * 100}
    else:  # base
        group_entry = {'Strategia': params['strategy_name']}

    result = {**group_entry, 'Campagna': campaign_num,
              'Successo (%)': round(success_rate, 2),
              'Fallimento (%)': round(failure_rate, 2),
              'Rilevamento (%)': round(detection_rate_pct, 2),
              'Passi Medi': round(avg_steps, 2),
              'Tempo Medio (h)': round(avg_time, 2),
              'Simulazioni Totali': total_simulations}

    return result


# Parallel campaign runner
def run_campaigns(dt_graph, mode, num_campaigns=10, check_interval=200, stabilization_threshold=1000, max_simulations=200000, skill=0.9, detection_rate=0.08, strategy_A_name=None, strategy_B_name=None, k_values=None, h_values=None, p_values=None, deviation_mode='stealth'):
    max_workers = multiprocessing.cpu_count()

    # Shorten strategy names for file names
    def _short_name(name):
        return (name.replace('ValueStrategy', '')
                     .replace('GoalOrientedStrategy', '')
                     .replace('Strategy', ''))

    # Default file name
    if mode == 'k':
        a, b = _short_name(strategy_A_name), _short_name(strategy_B_name)
        output_file = f"risultati_{a}_to_{b}.xlsx"
    elif mode == 'h':
        a, b = _short_name(strategy_A_name), _short_name(strategy_B_name)
        fixed_k = k_values[0] if k_values else 2
        output_file = f"risultati_H_{a}_to_{b}_K{fixed_k}.xlsx"
    elif mode == 'p':
        output_file = f"risultati_Stochastic_{deviation_mode}.xlsx"
    else:
        output_file = f"strategie_base_risultati.xlsx"

    # Serialize the graph
    dt_graph_data = nx.node_link_data(dt_graph)

    # Build the tasks for this mode
    tasks = []
    if mode == 'k':
        group_key = 'k'
        total = len(k_values) * num_campaigns
        print(f"Mode K | k={k_values} | {total} campagne")
        for k in k_values:
            for c in range(1, num_campaigns + 1):
                tasks.append({
                    'mode': 'k', 'campaign_num': c,
                    'dt_graph_data': dt_graph_data,
                    'strategy_A_name': strategy_A_name,
                    'strategy_B_name': strategy_B_name,
                    'k_value': k, 'h_value': None,
                    'check_interval': check_interval,
                    'stabilization_threshold': stabilization_threshold,
                    'max_simulations': max_simulations,
                    'skill': skill, 'detection_rate': detection_rate,
                })

    elif mode == 'h':
        group_key = 'h'
        fixed_k = k_values[0] if k_values else 2
        total = len(h_values) * num_campaigns
        print(f"Mode H | h={h_values}, k={fixed_k} | {total} campagne")
        for h in h_values:
            for c in range(1, num_campaigns + 1):
                tasks.append({
                    'mode': 'h', 'campaign_num': c,
                    'dt_graph_data': dt_graph_data,
                    'strategy_A_name': strategy_A_name,
                    'strategy_B_name': strategy_B_name,
                    'k_value': fixed_k, 'h_value': h,
                    'check_interval': check_interval,
                    'stabilization_threshold': stabilization_threshold,
                    'max_simulations': max_simulations,
                    'skill': skill, 'detection_rate': detection_rate,
                })

    elif mode == 'p':
        group_key = 'p (%)'
        total = len(p_values) * num_campaigns
        print(f"Mode P | p={[p*100 for p in p_values]}% | mode={deviation_mode} | {total} campagne")
        for p in p_values:
            for c in range(1, num_campaigns + 1):
                tasks.append({
                    'mode': 'p', 'campaign_num': c,
                    'dt_graph_data': dt_graph_data,
                    'p_value': p, 'deviation_mode': deviation_mode,
                    'check_interval': check_interval,
                    'stabilization_threshold': stabilization_threshold,
                    'max_simulations': max_simulations,
                    'skill': skill, 'detection_rate': detection_rate,
                })

    elif mode == 'base':
        group_key = 'Strategia'
        strategies = list(STRATEGY_MAP.keys())
        total = len(strategies) * num_campaigns
        print(f"Mode Base | {total} campagne")
        for strat_name in strategies:
            for c in range(1, num_campaigns + 1):
                tasks.append({
                    'mode': 'base', 'campaign_num': c,
                    'dt_graph_data': dt_graph_data,
                    'strategy_name': strat_name,
                    'check_interval': check_interval,
                    'stabilization_threshold': stabilization_threshold,
                    'max_simulations': max_simulations,
                    'skill': skill, 'detection_rate': detection_rate,
                })
    else:
        raise ValueError(f"Usa 'k', 'h', 'p' o 'base'.")

    # Run the campaigns in parallel
    all_results = []
    completed = 0
    total_tasks = len(tasks)
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        future_to_task = {executor.submit(run_single_campaign, task): task for task in tasks}
        for future in as_completed(future_to_task):
            task = future_to_task[future]
            try:
                result = future.result()
                all_results.append(result)
                completed += 1
                if completed % 50 == 0 or completed == total_tasks:
                    print(f"  [{completed}/{total_tasks}] completate")
            except Exception as exc:
                label = task.get('k_value') or task.get('h_value') or task.get('p_value') or task.get('strategy_name')
                print(f"Errore {group_key}={label}, C={task['campaign_num']}: {exc}")

    # Sort the results
    if mode == 'h':
        all_results.sort(key=lambda x: (-1 if x['h'] == 'None' else x['h'], x['Campagna']))
    elif mode == 'p':
        all_results.sort(key=lambda x: (x['p (%)'], x['Campagna']))
    else:
        all_results.sort(key=lambda x: (x[group_key], x['Campagna']))
    save_results(all_results, group_key, output_file)

    return output_file


# Entry point
if __name__ == "__main__":
    # Allow nested asyncio loops
    nest_asyncio.apply()
    
    # Config
    NVD_API_KEY = None 
    CSV_FILE_PATH = 'glpi.csv'
    
    # Build the digital twin
    dt = DigitalTwin()
    try:
        dt.load_from_csv(CSV_FILE_PATH)
    except FileNotFoundError:
        print(f"ERRORE: il file '{CSV_FILE_PATH}' non è stato trovato.")
        exit(1)
    
    # Add CVE data
    enricher = CVEEnricher(dt.get_graph(), api_key=NVD_API_KEY)
    asyncio.run(enricher.run_enrichment())
    
    # Campaign settings
    k_values = [5]
    h_values = [5, 10, 15, 20, 25, 30]
    num_campaigns = 100
    
    p_values_percent = [0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 4.0, 5.0, 7.0, 10.0]
    p_values = [p / 100.0 for p in p_values_percent]

    excel_file_h = run_campaigns(
        dt_graph=dt.get_graph(),
        mode='h',
        num_campaigns=num_campaigns,
        check_interval=200,
        stabilization_threshold=1000,
        max_simulations=200000,
        skill=0.9,
        detection_rate=0.08,
        strategy_A_name='MaxProbabilityStrategy',
        strategy_B_name='GreedyValueStrategy',
        k_values=k_values,
        h_values=h_values
    )
    excel_file_h1 = run_campaigns(
        dt_graph=dt.get_graph(),
        mode='h',
        num_campaigns=num_campaigns,
        check_interval=200,
        stabilization_threshold=1000,
        max_simulations=200000,
        skill=0.9,
        detection_rate=0.08,
        strategy_A_name='GreedyValueStrategy',
        strategy_B_name='StealthStrategy',
        k_values=k_values,
        h_values=h_values
    )
    excel_file_h2 = run_campaigns(
        dt_graph=dt.get_graph(),
        mode='h',
        num_campaigns=num_campaigns,
        check_interval=200,
        stabilization_threshold=1000,
        max_simulations=200000,
        skill=0.9,
        detection_rate=0.08,
        strategy_A_name='StealthStrategy',
        strategy_B_name='MaxProbabilityStrategy',
        k_values=k_values,
        h_values=h_values
    )
    excel_file_h3 = run_campaigns(
        dt_graph=dt.get_graph(),
        mode='h',
        num_campaigns=num_campaigns,
        check_interval=200,
        stabilization_threshold=1000,
        max_simulations=200000,
        skill=0.9,
        detection_rate=0.08,
        strategy_A_name='NoisyGoalOrientedStrategy',
        strategy_B_name='GreedyValueStrategy',
        k_values=k_values,
        h_values=h_values
    )
    excel_file_h4 = run_campaigns(
        dt_graph=dt.get_graph(),
        mode='h',
        num_campaigns=num_campaigns,
        check_interval=200,
        stabilization_threshold=1000,
        max_simulations=200000,
        skill=0.9,
        detection_rate=0.08,
        strategy_A_name='NoisyGoalOrientedStrategy',
        strategy_B_name='MaxProbabilityStrategy',
        k_values=k_values,
        h_values=h_values
    )