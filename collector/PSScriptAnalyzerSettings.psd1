@{
    # CI runs Invoke-ScriptAnalyzer -Severity Warning,Error with these settings and fails on any result.
    # Excluded on purpose:
    #   PSUseSingularNouns: private names such as Get-DDNetworkFacts and Merge-DDEndpoints describe what they return.
    #   PSUseShouldProcessForStateChangingFunctions: the New-*/Set-*/Update-* functions it flags are private helpers
    #     that build objects or write the collector's own state and output files, not system state.
    #   PSReviewUnusedParameter: reports parameters used inside script blocks (Invoke-DDStep -Script { ... }) as
    #     unused, which is how every collection step is written.
    # The tests are analysed with PSAvoidGlobalVars excluded as well: Pester mocks share fakes through $global:.
    Severity     = @('Warning', 'Error')
    ExcludeRules = @(
        'PSUseSingularNouns',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSReviewUnusedParameter'
    )
}
