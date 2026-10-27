namespace v2rayN.Desktop.Common;

/// <summary>
/// Keeps a combo box's drop-down on its screen.
/// </summary>
/// <remarks>
/// Avalonia sizes a drop-down to its items up to MaxDropDownHeight and does not shrink it to the screen. A long
/// list under a cap taller than the free space runs past the screen edge, and its ScrollViewer, sized to the whole
/// cap, cannot scroll the hidden items into view. WPF limits a popup to the screen by itself.
/// Just before the drop-down opens, the cap is lowered to the larger free space above or below the box, so the
/// list fits on that side and scrolls. The cap set in XAML stays the upper limit.
/// </remarks>
public static class DropDownFit
{
    // The popup's border and shadow take part of the free space.
    private const double EdgeMargin = 12;

    // A few rows stay visible even when the box sits at a screen edge.
    private const double MinHeight = 120;

    public static void Attach(ComboBox comboBox)
    {
        var maxHeight = comboBox.MaxDropDownHeight;
        // Tunnel handlers run before the box opens itself on a pointer release or a key.
        comboBox.AddHandler(InputElement.PointerPressedEvent, (_, _) => Fit(comboBox, maxHeight), RoutingStrategies.Tunnel, handledEventsToo: true);
        comboBox.AddHandler(InputElement.KeyDownEvent, (_, _) => Fit(comboBox, maxHeight), RoutingStrategies.Tunnel, handledEventsToo: true);
    }

    private static void Fit(ComboBox comboBox, double maxHeight)
    {
        if (comboBox.IsDropDownOpen)
        {
            return;
        }

        var screen = TopLevel.GetTopLevel(comboBox)?.Screens?.ScreenFromVisual(comboBox);
        if (screen == null)
        {
            comboBox.MaxDropDownHeight = maxHeight;
            return;
        }

        var top = comboBox.PointToScreen(new Point(0, 0)).Y;
        var bottom = comboBox.PointToScreen(new Point(0, comboBox.Bounds.Height)).Y;
        comboBox.MaxDropDownHeight = FitHeight(maxHeight, top, bottom, screen.WorkingArea.Y, screen.WorkingArea.Bottom, screen.Scaling);
    }

    // Screen positions are physical pixels; the result is in device-independent pixels.
    internal static double FitHeight(double maxHeight, double boxTop, double boxBottom, double workTop, double workBottom, double scaling)
    {
        var below = (workBottom - boxBottom) / scaling;
        var above = (boxTop - workTop) / scaling;
        var free = Math.Max(below, above) - EdgeMargin;
        return Math.Clamp(free, Math.Min(MinHeight, maxHeight), maxHeight);
    }
}
