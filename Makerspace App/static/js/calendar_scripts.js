
$(document).ready(function() {
    $('#calendar').fullCalendar({
        events: '/fetch_events', // Fetch events from the Flask route
        editable: false, // Make the calendar read-only
        eventColor: '#378006', // Set a default color for events

        dayClick: function(date, jsEvent, view) {
            // Clear the modal
            $('#modal-date').text('');
            $('#modal-events').html('');

            // Set the date in the modal
            $('#modal-date').text(date.format());

            // Fetch events for this day
            var events = $('#calendar').fullCalendar('clientEvents', function(event) {
                return moment(event.start).isSame(date, 'day');
            });

            // Add events to the modal
            $.each(events, function(i, event) {
                $('#modal-events').append('<p>' + event.title + '</p>');
            });

            // Show the modal
            $('#modal').show();
        }
    });
});
