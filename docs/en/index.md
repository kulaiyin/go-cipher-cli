---
layout: home

hero:
  name: go-cipher-cli
  text: Go CLI Tool
  tagline: Configuration management, structured logging, interactive prompts, progress bars, and one-click distribution via an APT repository
  actions:
    - theme: brand
      text: Quick Start
      link: /en/guide/installation
    - theme: alt
      text: Usage
      link: /en/guide/usage

features:
  - title: Cobra Command Framework
    details: Built with spf13/cobra, providing run / version subcommands and a comprehensive help system.
  - title: Viper Configuration
    details: Supports YAML/JSON/TOML config files, environment variables, and defaults. A custom path can be specified via --config.
  - title: Zap Structured Logging
    details: A global Logger is initialized at startup, supporting debug/info/warn/error levels.
  - title: Survey Interactive Prompts
    details: Supports operation type selection (Encrypt/Decrypt) and target name input.
  - title: MPB Progress Bar
    details: Displays progress in real time during task execution with clear feedback.
  - title: APT Repository Distribution
    details: Hosts .deb packages and APT repository metadata on GitHub Pages; clients can install via apt install.
---
