package submission

// ServiceModel creates a Submission from a given StoredSubmission.
func ServiceModel(storedSubmission *StoredSubmission) Submission {
	return Submission{
		Status:                 storedSubmission.Status.String(),
		Reason:                 storedSubmission.Reason,
		PresentationSubmission: &storedSubmission.Submission,
	}
}
