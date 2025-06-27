# GP4Net - Java Card Package AID Management
# Makefile for extracting and managing package AID mappings

.PHONY: help extract-aids update-submodules build-aid-db test-scanner clean-aids

# Default target
help:
	@echo "GP4Net AID Management Commands:"
	@echo ""
	@echo "  extract-aids       Extract package AIDs from Oracle Java Card SDKs"
	@echo "  update-submodules  Update Oracle SDK submodule to latest"
	@echo "  build-aid-db       Full rebuild of AID database (update + extract)"
	@echo "  test-scanner       Test AID scanner with sample files"
	@echo "  clean-aids         Remove generated AID database files"
	@echo "  analyze-exp FILE [SDK_VERSION] [DATABASE]   Analyze .exp file with optional SDK version and database save"
	@echo ""

# Extract AIDs from Oracle SDKs
extract-aids:
	@echo "Extracting package AIDs from Oracle Java Card SDKs..."
	dotnet run --project src/Gp4Net.Tool/Gp4Net.Tool.csproj -- \
		packages scan-sdk external/oracle_javacard_sdks \
		--output data/known-packages.json

# Update git submodules
update-submodules:
	@echo "Updating Oracle SDK submodule..."
	git submodule update --init --recursive
	git submodule update --remote external/oracle_javacard_sdks

# Full AID database rebuild
build-aid-db: update-submodules extract-aids
	@echo "AID database build complete!"
	@echo "Found packages:"
	@jq -r '.packageCount' data/known-packages.json 2>/dev/null || echo "Database created"

# Test scanner with sample files
test-scanner:
	@echo "Testing AID scanner with sample .exp files..."
	@find external/oracle_javacard_sdks -name "*.exp" | head -3 | while read file; do \
		echo "Analyzing: $$file"; \
		dotnet run --project src/Gp4Net.Tool/Gp4Net.Tool.csproj -- \
			packages analyze-exp "$$file"; \
		echo ""; \
	done

# Clean generated files
clean-aids:
	@echo "Cleaning generated AID database files..."
	rm -f data/known-packages.json
	rm -f oracle-packages.json
	rm -f oracle-packages-with-sdk.json
	rm -f globalplatform-packages.json

# Analyze individual .exp file (usage: make analyze-exp FILE=path/to/file.exp [SDK_VERSION=version] [DATABASE=path])
analyze-exp:
ifndef FILE
	@echo "Usage: make analyze-exp FILE=path/to/file.exp [SDK_VERSION=version] [DATABASE=path]"
	@exit 1
endif
	@echo "Analyzing .exp file: $(FILE)"
ifdef SDK_VERSION
	@echo "Using SDK version: $(SDK_VERSION)"
	ifdef DATABASE
		@echo "Saving to database: $(DATABASE)"
		dotnet run --project src/Gp4Net.Tool/Gp4Net.Tool.csproj -- \
			packages analyze-exp "$(FILE)" --detailed --sdk-version "$(SDK_VERSION)" --output "$(DATABASE)"
	else
		dotnet run --project src/Gp4Net.Tool/Gp4Net.Tool.csproj -- \
			packages analyze-exp "$(FILE)" --detailed --sdk-version "$(SDK_VERSION)"
	endif
else
	ifdef DATABASE
		@echo "Saving to database: $(DATABASE)"
		dotnet run --project src/Gp4Net.Tool/Gp4Net.Tool.csproj -- \
			packages analyze-exp "$(FILE)" --detailed --output "$(DATABASE)"
	else
		dotnet run --project src/Gp4Net.Tool/Gp4Net.Tool.csproj -- \
			packages analyze-exp "$(FILE)" --detailed
	endif
endif

# Advanced: scan specific SDK version
extract-aids-version:
ifndef VERSION
	@echo "Usage: make extract-aids-version VERSION=jc221_kit"
	@exit 1
endif
	@echo "Extracting AIDs from $(VERSION)..."
	dotnet run --project src/Gp4Net.Tool/Gp4Net.Tool.csproj -- \
		packages scan-sdk external/oracle_javacard_sdks/$(VERSION) \
		--output data/$(VERSION)-packages.json

# Show statistics about discovered packages
stats:
	@if [ -f src/Gp4Net/Data/known-packages.json ]; then \
		echo "AID Database Statistics:"; \
		echo "  Total packages: $$(jq -r '.packageCount' src/Gp4Net/Data/known-packages.json)"; \
		echo "  Generated: $$(jq -r '.generatedAt' src/Gp4Net/Data/known-packages.json)"; \
		echo ""; \
		echo "Package breakdown:"; \
		jq -r '.packages | to_entries[] | "  \(.key) -> \(.value.name) v\(.value.version) (\(.value.sdkVersion))"' src/Gp4Net/Data/known-packages.json | sort; \
	else \
		echo "No AID database found in src/Gp4Net/Data/known-packages.json"; \
	fi

# Validate CAP files with resolved package names (when implemented)
validate-with-names:
ifndef CAP_FILE
	@echo "Usage: make validate-with-names CAP_FILE=path/to/file.cap"
	@exit 1
endif
	@echo "Validating CAP file with resolved package names: $(CAP_FILE)"
	dotnet run --project src/Gp4Net.Tool/Gp4Net.Tool.csproj -- \
		applet validate "$(CAP_FILE)"

# Create data directory
data:
	mkdir -p data

# Ensure data directory exists for AID extraction
extract-aids: data