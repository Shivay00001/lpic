"""
Deterministic policy evaluation engine.
All evaluation is pure and side-effect free.
"""

from typing import List, Dict, Any

from ..config import DECISION_ALLOW, DECISION_DENY, DECISION_REQUIRE_REVIEW
from ..errors import PolicyEvaluationError
from ..db.connection import DatabaseConnection
from .model import Policy
from .conditions import evaluate_conditions


class PolicyEvaluator:
    """
    Evaluates authorization requests against policies.
    """
    
    def __init__(self, db: DatabaseConnection):
        """
        Initialize policy evaluator.
        
        Args:
            db: Database connection
        """
        self.db = db
    
    def add_policy(self, policy: Policy):
        """
        Add a policy to the database.
        
        Args:
            policy: Policy to add
        """
        import json
        
        conditions_json = json.dumps(policy.conditions) if policy.conditions else None
        
        with self.db.transaction():
            self.db.execute(
                """
                INSERT INTO policies (
                    policy_id, subject, resource, action, decision, conditions, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    policy.policy_id,
                    policy.subject,
                    policy.resource,
                    policy.action,
                    policy.decision,
                    conditions_json,
                    policy.created_at,
                )
            )
    
    def get_policy(self, policy_id: str) -> Policy:
        """
        Retrieve a policy by ID.
        
        Args:
            policy_id: Policy ID
            
        Returns:
            Policy object
            
        Raises:
            PolicyEvaluationError: If policy not found
        """
        import json
        
        row = self.db.fetch_one(
            "SELECT * FROM policies WHERE policy_id = ?",
            (policy_id,)
        )
        
        if not row:
            raise PolicyEvaluationError(f"Policy {policy_id} not found")
        
        conditions = json.loads(row['conditions']) if row['conditions'] else {}
        
        return Policy(
            policy_id=row['policy_id'],
            subject=row['subject'],
            resource=row['resource'],
            action=row['action'],
            decision=row['decision'],
            conditions=conditions,
            created_at=row['created_at'],
        )
    
    def list_policies(self) -> List[Policy]:
        """
        List all policies.
        
        Returns:
            List of Policy objects
        """
        import json
        
        rows = self.db.fetch_all("SELECT * FROM policies ORDER BY created_at")
        
        policies = []
        for row in rows:
            conditions = json.loads(row['conditions']) if row['conditions'] else {}
            policies.append(Policy(
                policy_id=row['policy_id'],
                subject=row['subject'],
                resource=row['resource'],
                action=row['action'],
                decision=row['decision'],
                conditions=conditions,
                created_at=row['created_at'],
            ))
        
        return policies
    
    def find_matching_policies(
        self,
        identity_id: str,
        resource: str,
        action: str,
    ) -> List[Policy]:
        """
        Find all policies that match a request.
        
        Args:
            identity_id: Identity making request
            resource: Resource being accessed
            action: Action being performed
            
        Returns:
            List of matching Policy objects
        """
        all_policies = self.list_policies()
        
        matching = []
        for policy in all_policies:
            if policy.matches_request(identity_id, resource, action):
                matching.append(policy)
        
        return matching
    
    def evaluate(
        self,
        identity_id: str,
        resource: str,
        action: str,
        context: Dict[str, Any],
    ) -> str:
        """
        Evaluate an authorization request.
        
        Evaluation logic:
        1. Find all matching policies
        2. Filter by condition evaluation
        3. Apply precedence: DENY > REQUIRE_REVIEW > ALLOW
        4. Default to DENY if no policies match
        
        Args:
            identity_id: Identity making request
            resource: Resource being accessed
            action: Action being performed
            context: Request context for condition evaluation
            
        Returns:
            Decision: ALLOW, DENY, or REQUIRE_REVIEW
        """
        try:
            # Find matching policies
            matching_policies = self.find_matching_policies(identity_id, resource, action)
            
            # No policies = DENY
            if not matching_policies:
                return DECISION_DENY
            
            # Evaluate conditions and collect decisions
            applicable_decisions = []
            
            for policy in matching_policies:
                # Evaluate conditions
                if policy.conditions:
                    try:
                        if not evaluate_conditions(policy.conditions, context):
                            continue  # Condition not satisfied
                    except Exception:
                        # Condition evaluation error = skip policy
                        continue
                
                applicable_decisions.append(policy.decision)
            
            # No applicable policies = DENY
            if not applicable_decisions:
                return DECISION_DENY
            
            # Apply precedence: DENY > REQUIRE_REVIEW > ALLOW
            if DECISION_DENY in applicable_decisions:
                return DECISION_DENY
            
            if DECISION_REQUIRE_REVIEW in applicable_decisions:
                return DECISION_REQUIRE_REVIEW
            
            if DECISION_ALLOW in applicable_decisions:
                return DECISION_ALLOW
            
            # Should never reach here
            return DECISION_DENY
            
        except Exception as e:
            raise PolicyEvaluationError(f"Policy evaluation failed: {e}")
    
    def delete_policy(self, policy_id: str):
        """
        Delete a policy.
        
        Args:
            policy_id: Policy ID to delete
        """
        with self.db.transaction():
            self.db.execute(
                "DELETE FROM policies WHERE policy_id = ?",
                (policy_id,)
            )
    
    def delete_all_policies(self):
        """
        Delete all policies.
        WARNING: Use with caution.
        """
        with self.db.transaction():
            self.db.execute("DELETE FROM policies")
