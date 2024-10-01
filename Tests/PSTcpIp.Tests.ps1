#requires -Module Pester
#requires -Module PSScriptAnalyzer
#requires -Module InjectionHunter

$myDefaultDirectory = Get-Location

Set-Location -Path $myDefaultDirectory
Set-Location -Path ..

$module = 'PSTcpIp'

$moduleDirectory = Get-Item -Path $myDefaultDirectory | Select-Object -ExpandProperty FullName

Clear-Host

Describe "$module Module Structure and Validation Tests" -Tag Unit -WarningAction SilentlyContinue {
    Context "$module" {
        It "has the root module $module.psm1" {
            "$moduleDirectory/$module.psm1" | Should -Exist
        }

        It "has the a manifest file of $module.psd1" {
            "$moduleDirectory/$module.psd1" | Should -Exist
        }

        It "$module is valid PowerShell code" {
            $psFile = Get-Content -Path "$moduleDirectory\$module.psm1" -ErrorAction Stop
            $errors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize($psFile, [ref]$errors)
            $errors.Count | Should -Be 0
        }
    }

    Context "Code Validation" {
        Get-ChildItem -Path "$moduleDirectory" -Filter *.ps1 -Recurse | ForEach-Object {
            It "$_ is valid PowerShell code" {
                $psFile = Get-Content -Path $_.FullName -ErrorAction Stop
                $errors = $null
                $null = [System.Management.Automation.PSParser]::Tokenize($psFile, [ref]$errors)
                $errors.Count | Should -Be 0
            }
        }
    }

    Context "$module.psd1" {
        It "should not throw an exception in import" {
            $modPath = "$moduleDirectory/$module.psd1"
            { Import-Module -Name $modPath -Force -ErrorAction Stop } | Should Not Throw
        }
    }

}

Describe "Testing module and cmdlets" -Tag Unit -WarningAction SilentlyContinue {
    $scriptAnalyzerRules = Get-ScriptAnalyzerRule

    $modulePath = "$moduleDirectory\$module.psm1"

    <#
        1. PSReviewUnusedParameter is excluded due to false positives for private method Get-WebServerCertificate and Get-TlsInformation for the $callback variable (which is used literally the next line).
        2. PSAvoidUsingEmptyCatchBlock is excluded due to the necessary use of an empty catch block for Invoke-DnsEnumeration to not stop when an exception occurs when calling [System.Net.Dns]::GetHostAddresses()
        3. PSAvoidUsingWriteHost is very intentionally excluded in for the private function Invoke-TimedWait as I do not want the status messages to ever reach the pipeline.
    #>

    Context "$module test against PSSA rules" {
        $analysis = Invoke-ScriptAnalyzer -Path $modulePath -ExcludeRule PSReviewUnusedParameter, PSAvoidUsingEmptyCatchBlock, PSAvoidUsingWriteHost, PSUseShouldProcessForStateChangingFunctions

        foreach ($rule in $scriptAnalyzerRules) {
            It "should pass $rule" {
                If ($analysis.RuleName -contains $rule) {
                    $analysis | Where-Object RuleName -eq $rule -OutVariable failures
                    $failures.Count | Should -Be 0
                }
            }
        }
    }

    Context "$module test against InjectionHunter rules" {
        $injectionHunterModulePath = Get-Module -Name InjectionHunter -ListAvailable | Select-Object -ExpandProperty Path

        $analysis = Invoke-ScriptAnalyzer -Path $modulePath -CustomRulePath $injectionHunterModulePath

        foreach ($rule in $scriptAnalyzerRules) {
            It "should pass $rule" {
                If ($analysis.RuleName -contains $rule) {
                    $analysis | Where-Object RuleName -eq $rule -OutVariable failures
                    $failures.Count | Should -Be 0
                }
            }
        }
    }
}
