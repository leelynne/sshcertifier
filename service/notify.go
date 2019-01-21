package service

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatchevents"
	"github.com/pkg/errors"
)

func (sc *SSHCertifier) NotifyIssue(ctx context.Context) error {
	cwsrv := cloudwatchevents.New(sc.awssess)
	req := &cloudwatchevents.PutEventsInput{
		Entries: []*cloudwatchevents.PutEventsRequestEntry{
			&cloudwatchevents.PutEventsRequestEntry{
				Time:       aws.Time(time.Now()),
				Source:     aws.String("sshcertifier"),
				DetailType: aws.String("cert-issued"),
			},
		},
	}
	_, err := cwsrv.PutEventsWithContext(ctx, req)
	if err != nil {
		return errors.Wrapf(err, "Failed to put cloudwatch event")
	}
	return nil
}
