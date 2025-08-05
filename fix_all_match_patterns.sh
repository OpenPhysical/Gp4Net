#!/bin/bash

cd /Users/mistial/Projects/Gp4Net

echo "Fixing all MatchAsync patterns in Tool project..."

# Fix in LoadCliCommand.cs
echo "Fixing LoadCliCommand.cs..."
perl -i -0pe 's/return await result\.MatchAsync\(\s*async installResult[^}]+\}\s*,\s*error[^}]+\}\s*\);/if (result.IsSuccess)\n                    {\n                        var installResult = result.Value;\n                        ctx.Display.Success($"Successfully loaded {settings.CapFile}");\n                        ctx.Display.Success($"  Load File AID:    {Convert.ToHexString(installResult.LoadFileAid)}");\n                        ctx.Display.Success($"  Executable AIDs:");\n                        \n                        foreach (var aid in installResult.ExecutableAids)\n                        {\n                            ctx.Display.Success($"    - {Convert.ToHexString(aid)}");\n                        }\n                        \n                        return 0;\n                    }\n                    else\n                    {\n                        ctx.Display.Error($"Failed to load CAP file: {result.Error.Message}");\n                        return 1;\n                    }/gs' src/Gp4Net.Tool/Commands/Applet/LoadCliCommand.cs

# Fix in ListCliCommand.cs  
echo "Fixing ListCliCommand.cs..."
perl -i -0pe 's/return await statusResult\.MatchAsync<int>\(\s*async applications[^}]+\}\s*,\s*error[^}]+\}\s*\);/if (statusResult.IsSuccess)\n            {\n                var applications = statusResult.Value;\n                return await DisplayApplications(applications, settings);\n            }\n            else\n            {\n                return HandleError(statusResult.Error);\n            }/gs' src/Gp4Net.Tool/Commands/Applet/ListCliCommand.cs

# Fix in InstallCliCommand.cs
echo "Fixing InstallCliCommand.cs..."
perl -i -0pe 's/return await result\.MatchAsync\(\s*async installResult[^}]+\}\s*,\s*error[^}]+\}\s*\);/if (result.IsSuccess)\n                    {\n                        var installResult = result.Value;\n                        ctx.Display.Success($"Successfully installed {settings.CapFile}");\n                        ctx.Display.Success($"  Application AID: {Convert.ToHexString(installResult.ApplicationAid)}");\n                        return 0;\n                    }\n                    else\n                    {\n                        ctx.Display.Error($"Failed to install CAP file: {result.Error.Message}");\n                        return 1;\n                    }/gs' src/Gp4Net.Tool/Commands/Applet/InstallCliCommand.cs

# Fix in KeysChangeCommand.cs
echo "Fixing KeysChangeCommand.cs..."
perl -i -0pe 's/return await putKeysResult\.MatchAsync<int>\(\s*async _[^}]+\}\s*,\s*async error[^}]+\}\s*\);/if (putKeysResult.IsSuccess)\n                    {\n                        ctx.Display.Success("Keys successfully changed");\n                        return 0;\n                    }\n                    else\n                    {\n                        ctx.Display.Error($"Failed to change keys: {putKeysResult.Error.Message}");\n                        return 1;\n                    }/gs' src/Gp4Net.Tool/Commands/Card/KeysChangeCommand.cs

# Fix in GetIsdDataCommand.cs
echo "Fixing GetIsdDataCommand.cs..."
# First occurrence
perl -i -0pe 's/await cardInfoResult\.MatchAsync\(\s*cardInfo[^}]+\}\s*,\s*error[^}]+\}\s*\)/if (cardInfoResult.IsSuccess)\n                {\n                    var cardInfo = cardInfoResult.Value;\n                    DisplayCardInfo(ctx, cardInfo);\n                }\n                else\n                {\n                    ctx.Display.Error($"Failed to get card info: {cardInfoResult.Error.Message}");\n                }/gs' src/Gp4Net.Tool/Commands/Card/GetIsdDataCommand.cs

# Second occurrence
perl -i -0pe 's/await keyInfoResult\.MatchAsync\(\s*keyInfo[^}]+\}\s*,\s*error[^}]+\}\s*\)/if (keyInfoResult.IsSuccess)\n                {\n                    var keyInfo = keyInfoResult.Value;\n                    DisplayKeyInfo(ctx, keyInfo);\n                }\n                else\n                {\n                    ctx.Display.Error($"Failed to get key info: {keyInfoResult.Error.Message}");\n                }/gs' src/Gp4Net.Tool/Commands/Card/GetIsdDataCommand.cs

# Third occurrence
perl -i -0pe 's/await result\.MatchAsync\(\s*data[^}]+\}\s*,\s*error[^}]+\}\s*\)/if (result.IsSuccess)\n                        {\n                            var data = result.Value;\n                            ctx.Display.Information($"Tag {tagName}: {Convert.ToHexString(data)}");\n                        }\n                        else\n                        {\n                            ctx.Display.Warning($"Tag {tagName}: Not available");\n                        }/gs' src/Gp4Net.Tool/Commands/Card/GetIsdDataCommand.cs

# Fix in InfoCommand.cs
echo "Fixing InfoCommand.cs..."
perl -i -0pe 's/await cplcResult\.MatchAsync\(\s*cplcData[^}]+\}\s*,\s*_[^}]+\}\s*\)/if (cplcResult.IsSuccess)\n            {\n                var cplcData = cplcResult.Value;\n                DisplayCplcData(ctx, cplcData);\n            }\n            else\n            {\n                ctx.Display.Warning("CPLC data not available");\n            }/gs' src/Gp4Net.Tool/Commands/Card/InfoCommand.cs

# Fix in DeleteCommand.cs
echo "Fixing DeleteCommand.cs..."
# First occurrence
perl -i -0pe 's/await statusResult\.MatchAsync\(\s*applications[^;]+;/if (statusResult.IsSuccess)\n                        {\n                            var applications = statusResult.Value;\n                            relatedApplications = applications\n                                .Where(app => {\n                                    var aidHex = Convert.ToHexString(app.Aid);\n                                    return packagesAids.Contains(aidHex) || executableAids.Contains(aidHex);\n                                })\n                                .ToList();\n                        }\n                        else\n                        {\n                            ctx.Display.Warning($"Could not get related applications: {statusResult.Error.Message}");\n                            relatedApplications = new List<ApplicationInfo>();\n                        }/gs' src/Gp4Net.Tool/Commands/Applet/DeleteCommand.cs

# Second occurrence
perl -i -0pe 's/return await deleteResult\.MatchAsync\(\s*async _[^}]+\}\s*,\s*error[^}]+\}\s*\);/if (deleteResult.IsSuccess)\n                    {\n                        ctx.Display.Success($"Successfully deleted {aidToDelete}");\n                        return 0;\n                    }\n                    else\n                    {\n                        ctx.Display.Error($"Failed to delete: {deleteResult.Error.Message}");\n                        return 1;\n                    }/gs' src/Gp4Net.Tool/Commands/Applet/DeleteCommand.cs

# Third occurrence - SelectApplication
perl -i -0pe 's/await selectResult\.MatchAsync\(\s*response[^}]+\}\s*,\s*_[^}]+\}\s*\);/if (selectResult.IsSuccess)\n            {\n                var response = selectResult.Value;\n                ctx.Display.Success($"Application {Convert.ToHexString(aid)} is installed");\n                if (response.Fci?.ApplicationData != null)\n                {\n                    ctx.Display.Information($"  App Data: {Convert.ToHexString(response.Fci.ApplicationData)}");\n                }\n                return true;\n            }\n            else\n            {\n                ctx.Display.Information($"Application {Convert.ToHexString(aid)} is not installed");\n                return false;\n            }/gs' src/Gp4Net.Tool/Commands/Applet/DeleteCommand.cs

echo "All MatchAsync patterns fixed!"