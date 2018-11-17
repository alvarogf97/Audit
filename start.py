from audit.core.agent import Agent

if __name__ == "__main__":
    agent = Agent(5000)
    agent.serve_forever()