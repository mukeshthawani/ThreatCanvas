from setuptools import setup, find_packages

setup(
	name="threatcanvas",
	version="0.1",
	packages=find_packages(),
	description="A threat modeling tool using LLMs",
	author="ThreatCanvas Team",
	install_requires=[
		"openai",  
		"requests", 
        "pydantic",
        "python-dotenv"
	],
	python_requires=">=3.7",
)