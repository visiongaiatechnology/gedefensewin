# STATUS: DIAMANT VGT SUPREME
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Set-VgtDefenderBaseline {
    param([Parameter(Mandatory)][pscustomobject]$Profile)
    $status = Get-MpComputerStatus
    if (-not $status.AntivirusEnabled) { throw [InvalidOperationException]::new('Microsoft Defender Antivirus is not active.') }

    Set-MpPreference -PUAProtection Enabled
    Set-MpPreference -MAPSReporting Advanced
    Set-MpPreference -SubmitSamplesConsent SendSafeSamples
    Set-MpPreference -EnableNetworkProtection Enabled
    Set-MpPreference -CloudBlockLevel $Profile.cloudBlockLevel
    Set-MpPreference -EnableControlledFolderAccess $Profile.controlledFolderAccess

    $ids = @(
        '56a863a9-875e-4185-98a7-b882c64b5ce5',
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a',
        '3b576869-a4ec-4529-8536-b80a7769e899',
        '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84',
        'd3e037e1-3eb8-44c8-a917-57927947596d',
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc',
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550',
        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4',
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2',
        'c1db55ab-c21a-4637-bb3f-a12568109d35',
        '33ddedf1-c6e0-47cb-833e-de6133960387'
    )
    $actions = @($ids | ForEach-Object { $Profile.asrMode })
    Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $actions
}

Export-ModuleMember -Function Set-VgtDefenderBaseline
