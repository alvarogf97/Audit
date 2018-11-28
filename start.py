"""
 supported os:
    windows 7,8,10
    linux:
        - debian based distributions
        - rhel based distribution
        - arch based distributions
    MacOs X

"""

from audit.core.agent import Agent

if __name__ == "__main__":
    agent = Agent(5000)
    agent.serve_forever()