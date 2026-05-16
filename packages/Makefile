.PHONY: deploy
deploy:
	@echo "Deploying packages from GitHub releases (default: 5 versions)..."
	@gh workflow run deploy.yml

.PHONY: deploy-all
deploy-all:
	@echo "Deploying ALL versions from GitHub releases..."
	@gh workflow run deploy.yml -f keep_versions=100
